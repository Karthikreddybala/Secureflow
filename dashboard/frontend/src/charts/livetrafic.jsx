import React, { useMemo, useState } from 'react';
import { Table } from 'react-bootstrap';

const PROTOCOL_MAP = {
  '6': 'TCP',
  '17': 'UDP',
  '1': 'ICMP'
};

function resolveProtocol(value) {
  if (value === undefined || value === null || value === '') {
    return 'Unknown';
  }

  const key = String(value);
  return PROTOCOL_MAP[key] || key;
}

function formatTime(value) {
  if (!value) {
    return 'N/A';
  }

  return new Date(value).toLocaleTimeString();
}

function LiveTrafficTable({ data, isPaused }) {
  const [protocolFilter, setProtocolFilter] = useState('all');
  const [searchValue, setSearchValue] = useState('');

  const filteredRows = useMemo(() => {
    const query = searchValue.trim().toLowerCase();

    return data.filter((entry) => {
      const protocolName = resolveProtocol(entry.proto || entry.protocol);
      const matchesProtocol = protocolFilter === 'all' || protocolName === protocolFilter;

      const source = `${entry.src || entry.src_ip || ''}:${entry.sport || ''}`.toLowerCase();
      const destination = `${entry.dst || entry.dst_ip || ''}:${entry.dport || ''}`.toLowerCase();
      const info = String(entry.info || '').toLowerCase();
      const matchesSearch =
        query.length === 0 || source.includes(query) || destination.includes(query) || info.includes(query) || protocolName.toLowerCase().includes(query);

      return matchesProtocol && matchesSearch;
    });
  }, [data, protocolFilter, searchValue]);

  return (
    <div className="live-table-wrap">
      <div className="live-table-controls">
        <div className="live-table-control-group">
          <label htmlFor="protocol-filter">Protocol</label>
          <select id="protocol-filter" value={protocolFilter} onChange={(event) => setProtocolFilter(event.target.value)}>
            <option value="all">All</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </div>

        <div className="live-table-control-group search">
          <label htmlFor="traffic-search">Search</label>
          <input
            id="traffic-search"
            type="text"
            value={searchValue}
            onChange={(event) => setSearchValue(event.target.value)}
            placeholder="IP, protocol, or info"
          />
        </div>

        <div className="live-table-state">
          <span className={`live-state-pill ${isPaused ? 'paused' : 'live'}`}>{isPaused ? 'Paused' : 'Live'}</span>
          <span className="live-count-pill">Showing {filteredRows.length}</span>
        </div>
      </div>

      <div className="live-table-scroll">
        <Table className="live-traffic-table" hover responsive>
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Ports</th>
              <th>Size</th>
              <th>Info</th>
            </tr>
          </thead>
          <tbody>
            {filteredRows.length === 0 ? (
              <tr>
                <td colSpan={7} className="live-table-empty">
                  No traffic rows match current filters.
                </td>
              </tr>
            ) : (
              filteredRows.map((entry, index) => {
                const protocol = resolveProtocol(entry.proto || entry.protocol);
                const source = entry.src || entry.src_ip || 'Unknown';
                const destination = entry.dst || entry.dst_ip || 'Unknown';
                const sourcePort = entry.sport || '-';
                const destinationPort = entry.dport || '-';

                return (
                  <tr key={`${entry.timestamp || 'row'}-${source}-${destination}-${index}`}>
                    <td>{formatTime(entry.timestamp)}</td>
                    <td>
                      <code>{source}</code>
                    </td>
                    <td>
                      <code>{destination}</code>
                    </td>
                    <td>
                      <span className={`protocol-pill ${protocol.toLowerCase()}`}>{protocol}</span>
                    </td>
                    <td>
                      {sourcePort} -&gt; {destinationPort}
                    </td>
                    <td>{entry.size || entry.bytes || 'N/A'}</td>
                    <td className="live-info-cell">{entry.info || 'Packet event'}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </Table>
      </div>
    </div>
  );
}

export default LiveTrafficTable;
