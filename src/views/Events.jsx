import EventsTable from '../components/EventsTable.jsx';

export default function Events({ dataset, analysis, filter, onClearFilter, nav }) {
  return (
    <div className="page">
      <p className="lead">
        Los {dataset.events.length} eventos del archivo original, sin modificar. La columna <b>Criticidad</b> es la
        asignada por el análisis; <b>Severity SIEM</b> se muestra solo como referencia. Haga clic en una fila para ver el
        detalle.
      </p>
      <EventsTable dataset={dataset} analysis={analysis} filter={filter} onClearFilter={onClearFilter} onOpenFinding={nav.openFinding} />
    </div>
  );
}
