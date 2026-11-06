import OpenAI from 'openai';
import { z } from 'zod';

export const AI_MODEL = process.env.AI_MODEL || 'gpt-5.4-mini';

const NarrativeSchema = z.object({
  resumen_ejecutivo: z.string(),
  valoracion_riesgo: z.string(),
  incidentes: z.array(z.object({ id: z.string(), narrativa: z.string(), impacto: z.string() })),
  conclusiones: z.string(),
  recomendaciones: z.array(z.string()),
  limitaciones: z.string(),
});

// JSON Schema estricto (Structured Outputs): todos los campos obligatorios y sin propiedades extra
const RESPONSE_FORMAT = {
  type: 'json_schema',
  json_schema: {
    name: 'narrativa_informe_soc',
    strict: true,
    schema: {
      type: 'object',
      additionalProperties: false,
      required: ['resumen_ejecutivo', 'valoracion_riesgo', 'incidentes', 'conclusiones', 'recomendaciones', 'limitaciones'],
      properties: {
        resumen_ejecutivo: { type: 'string' },
        valoracion_riesgo: { type: 'string' },
        incidentes: {
          type: 'array',
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['id', 'narrativa', 'impacto'],
            properties: { id: { type: 'string' }, narrativa: { type: 'string' }, impacto: { type: 'string' } },
          },
        },
        conclusiones: { type: 'string' },
        recomendaciones: { type: 'array', items: { type: 'string' } },
        limitaciones: { type: 'string' },
      },
    },
  },
};

const SYSTEM_PROMPT = `Eres un analista SOC de nivel 2 que redacta en español el informe de una investigación de seguridad para una consultora de ciberseguridad.

Recibirás un JSON con los resultados de un motor de detección determinista: incidentes, hallazgos, criticidad ya asignada y evidencias identificadas por Log_ID. Tu tarea es solo redactar; la detección y la clasificación ya están hechas.

Reglas obligatorias:
- Usa únicamente los datos del JSON. No inventes equipos, cuentas, IPs, horas, volúmenes, archivos ni Log_ID.
- Cita los Log_ID exactamente como aparecen (formato EVT-00000) para respaldar cada afirmación técnica.
- Respeta la criticidad asignada a cada incidente y hallazgo; no la cambies.
- Cuando algo no pueda concluirse con los registros (por ejemplo, el contenido de un comando codificado o la relación entre incidentes), dilo explícitamente y márcalo como "Hipótesis:" indicando qué evidencia adicional haría falta.
- No uses relleno ni frases genéricas que no se apoyen en los datos.

Según la audiencia:
- "ejecutivo": lenguaje claro para la dirección, sin jerga técnica; explica qué pasó, a qué datos o procesos de negocio afecta y qué decisiones urgentes se requieren. Puedes omitir los Log_ID en el resumen ejecutivo, pero no en las narrativas por incidente.
- "tecnico": precisión para el equipo de respuesta; secuencia de acciones del atacante, técnicas MITRE ATT&CK y evidencias.

Campos de salida:
- resumen_ejecutivo: un máximo de 250 palabras.
- valoracion_riesgo: 2-4 frases que justifiquen el nivel de riesgo global recibido.
- incidentes: un elemento por cada incidente o anomalía del JSON, con el mismo id; "narrativa" cuenta la secuencia de lo ocurrido citando Log_ID; "impacto" describe el efecto en confidencialidad, integridad, disponibilidad, operación y reputación.
- conclusiones: conclusión global, incluida la relación (o la falta de evidencia de relación) entre incidentes.
- recomendaciones: entre 6 y 10 recomendaciones concretas y accionables derivadas de los hallazgos.
- limitaciones: qué no puede determinarse con los registros disponibles.`;

export class AiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

let client;

export function aiStatus() {
  return { provider: 'OpenAI', model: AI_MODEL, configured: Boolean(process.env.OPENAI_API_KEY) };
}

const LOG_ID_RE = /EVT-\d{5}/g;
const NO_KEY = 'IA no configurada: defina OPENAI_API_KEY en el archivo .env del servidor y reinícielo.';

export async function draftNarrative({ audience, context }) {
  if (!process.env.OPENAI_API_KEY) throw new AiError(NO_KEY, 503);
  client ??= new OpenAI();

  let completion;
  try {
    completion = await client.chat.completions.create({
      model: AI_MODEL,
      max_completion_tokens: 16000,
      response_format: RESPONSE_FORMAT,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: `Audiencia: ${audience}\n\nResultados del análisis (JSON):\n${JSON.stringify(context)}` },
      ],
    });
  } catch (err) {
    if (err instanceof OpenAI.AuthenticationError) throw new AiError('La clave de OpenAI no es válida o fue revocada.', 503);
    if (err instanceof OpenAI.PermissionDeniedError) throw new AiError(`La clave no tiene acceso al modelo ${AI_MODEL}.`, 503);
    if (err instanceof OpenAI.NotFoundError) throw new AiError(`El modelo ${AI_MODEL} no existe o no está disponible: cambie AI_MODEL en .env.`, 503);
    if (err instanceof OpenAI.RateLimitError) throw new AiError('Límite de uso o saldo de OpenAI agotado. Revise la facturación de su cuenta.', 429);
    if (err instanceof OpenAI.APIConnectionError) throw new AiError('No se pudo conectar con OpenAI.', 502);
    if (err instanceof OpenAI.APIError) throw new AiError(`Error del servicio de IA (${err.status}): ${err.message}`, 502);
    throw err;
  }

  const choice = completion.choices[0];
  if (choice.message.refusal) throw new AiError('El modelo declinó redactar el informe. Use la redacción por plantilla.', 502);
  if (choice.finish_reason === 'length') throw new AiError('La respuesta de la IA llegó incompleta. Vuelva a intentarlo.', 502);

  let narrative;
  try {
    narrative = NarrativeSchema.parse(JSON.parse(choice.message.content));
  } catch {
    throw new AiError('La IA devolvió una respuesta con formato inválido. Vuelva a intentarlo.', 502);
  }

  // Control anti-alucinación: todo Log_ID citado debe existir en el contexto enviado
  const known = new Set(JSON.stringify(context).match(LOG_ID_RE) || []);
  const cited = new Set(JSON.stringify(narrative).match(LOG_ID_RE) || []);
  const unknownIds = [...cited].filter((id) => !known.has(id));

  return {
    narrative,
    model: completion.model,
    unknownIds,
    usage: { input: completion.usage?.prompt_tokens ?? 0, output: completion.usage?.completion_tokens ?? 0 },
  };
}
