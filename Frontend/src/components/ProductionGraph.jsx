import React, { useState, useEffect } from 'react';
import '../styles/ProductionGraph.css';

export default function ProductionGraph() {
  const [graphData, setGraphData] = useState(null);
  const [floorId, setFloorId] = useState(null);
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [chartType, setChartType] = useState('efficiency'); // efficiency, quality, production

  useEffect(() => {
    // Get floor from user data stored in localStorage
    let id = null;
    const floorManagerUser = localStorage.getItem('floorManagerUser');
    const adminUser = localStorage.getItem('adminUser');
    const workerUser = localStorage.getItem('workerUser');
    
    let userData = null;
    if (floorManagerUser) userData = JSON.parse(floorManagerUser);
    if (adminUser) userData = JSON.parse(adminUser);
    if (workerUser) userData = JSON.parse(workerUser);
    
    if (userData?.assignedFloorId) {
      id = userData.assignedFloorId;
      setFloorId(id);
    }

    // Initialize dates
    const today = new Date();
    const thirtyDaysAgo = new Date(today.getTime() - (30 * 24 * 60 * 60 * 1000));
    
    setStartDate(thirtyDaysAgo.toISOString().split('T')[0]);
    setEndDate(today.toISOString().split('T')[0]);
  }, []);

  const fetchGraphData = async () => {
    if (!startDate || !endDate) {
      setError('Please select both start and end dates');
      return;
    }

    setLoading(true);
    setError('');
    
    try {
      const token = localStorage.getItem('authToken');
      const params = new URLSearchParams({
        startDate: `${startDate}T00:00:00Z`,
        endDate: `${endDate}T23:59:59Z`
      });

      if (floorId) {
        params.append('floorId', floorId);
      }

      const response = await fetch(
        `http://localhost:5000/api/production-records/report/date-range?${params}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }
      );

      if (!response.ok) {
        throw new Error(`Failed to fetch data: ${response.statusText}`);
      }

      const data = await response.json();
      processGraphData(data.records);
    } catch (err) {
      console.error('Error fetching graph data:', err);
      setError(err.message || 'Failed to load graph data');
    } finally {
      setLoading(false);
    }
  };

  const processGraphData = (records) => {
    // Group records by date
    const groupedByDate = {};
    records.forEach(record => {
      const date = new Date(record.date).toLocaleDateString();
      if (!groupedByDate[date]) {
        groupedByDate[date] = [];
      }
      groupedByDate[date].push(record);
    });

    // Calculate daily averages
    const processedData = Object.entries(groupedByDate).map(([date, dayRecords]) => {
      const avgEfficiency = Math.round(
        dayRecords.reduce((sum, r) => sum + r.efficiency, 0) / dayRecords.length
      );
      const avgQuality = parseFloat(
        (dayRecords.reduce((sum, r) => sum + (r.qualityRate || 0), 0) / dayRecords.length).toFixed(1)
      );
      const totalProduced = dayRecords.reduce((sum, r) => sum + r.produced, 0);
      const totalTarget = dayRecords.reduce((sum, r) => sum + r.target, 0);

      return {
        date,
        efficiency: avgEfficiency,
        quality: avgQuality,
        produced: totalProduced,
        target: totalTarget,
        count: dayRecords.length
      };
    });

    setGraphData(processedData);
  };

  const getChartData = () => {
    if (!graphData) return [];
    
    switch (chartType) {
      case 'efficiency':
        return graphData.map(d => ({ date: d.date, value: d.efficiency, max: 100 }));
      case 'quality':
        return graphData.map(d => ({ date: d.date, value: d.quality, max: 100 }));
      case 'production':
        return graphData.map(d => ({ date: d.date, value: d.produced, target: d.target, max: d.target }));
      default:
        return [];
    }
  };

  const renderChart = () => {
    const data = getChartData();
    if (data.length === 0) return null;

    const maxValue = Math.max(...data.map(d => d.max || 0), 100);
    const chartHeight = 350;
    const padding = { top: 50, right: 30, bottom: 80, left: 70 };
    const plotHeight = chartHeight - padding.top - padding.bottom;
    const plotWidth = Math.max(600, data.length * 70); // Better spacing
    const barWidth = Math.min(50, (plotWidth / data.length) * 0.6);
    const barSpacing = plotWidth / data.length;

    return (
      <svg viewBox={`0 0 ${plotWidth + padding.left + padding.right} ${chartHeight}`} 
           className="chart-svg"
           preserveAspectRatio="xMidYMid meet">
        
        {/* Background */}
        <rect x={padding.left} y={padding.top} width={plotWidth} height={plotHeight} fill="#FAFAFA" stroke="#E5E7EB" strokeWidth="1" />

        {/* Grid lines */}
        {[0, 0.25, 0.5, 0.75, 1].map((ratio, i) => {
          const y = padding.top + plotHeight * (1 - ratio);
          const value = Math.round(maxValue * ratio);
          return (
            <g key={`grid-${i}`}>
              <line x1={padding.left} y1={y} x2={padding.left + plotWidth} y2={y} stroke="#E0E7FF" strokeWidth="1" strokeDasharray="3,3" />
              <text x={padding.left - 15} y={y + 5} textAnchor="end" fontSize="12" fill="#333" fontWeight="600">
                {value}
              </text>
            </g>
          );
        })}

        {/* Axis lines */}
        <line x1={padding.left} y1={padding.top + plotHeight} x2={padding.left + plotWidth} y2={padding.top + plotHeight} stroke="#1B4332" strokeWidth="2" />
        <line x1={padding.left} y1={padding.top} x2={padding.left} y2={padding.top + plotHeight} stroke="#1B4332" strokeWidth="2" />

        {/* Bars */}
        {data.map((point, idx) => {
          const x = padding.left + (idx + 0.5) * barSpacing - barWidth / 2;
          const ratio = point.value / (maxValue || 1);
          const height = plotHeight * ratio;
          const y = padding.top + plotHeight - height;

          let fillColor = '#10B981';
          if (chartType === 'efficiency') {
            fillColor = point.value >= 90 ? '#10B981' : point.value >= 80 ? '#F59E0B' : '#EF4444';
          } else if (chartType === 'quality') {
            fillColor = point.value >= 97 ? '#10B981' : point.value >= 95 ? '#F59E0B' : '#EF4444';
          } else if (chartType === 'production') {
            fillColor = '#3B82F6';
          }

          return (
            <g key={`bar-${idx}`}>
              <rect
                x={x}
                y={y}
                width={barWidth}
                height={height}
                fill={fillColor}
                opacity="0.85"
                rx="3"
              >
                <title>{`${point.date}: ${point.value}${chartType === 'production' ? ' units' : '%'}`}</title>
              </rect>
              {/* Value label on bar */}
              <text
                x={x + barWidth / 2}
                y={y - 8}
                textAnchor="middle"
                fontSize="11"
                fill="#333"
                fontWeight="600"
              >
                {point.value}
              </text>
            </g>
          );
        })}

        {/* X-axis labels */}
        {data.map((point, idx) => {
          const x = padding.left + (idx + 0.5) * barSpacing;
          return (
            <text
              key={`label-${idx}`}
              x={x}
              y={padding.top + plotHeight + 25}
              textAnchor="middle"
              fontSize="12"
              fill="#333"
              fontWeight="600"
            >
              {point.date}
            </text>
          );
        })}

        {/* Y-axis label */}
        <text x={20} y={30} fontSize="13" fill="#1B4332" fontWeight="700">
          {chartType === 'efficiency' ? 'Efficiency %' : chartType === 'quality' ? 'Quality %' : 'Production Units'}
        </text>

        {/* Chart title */}
        <text x={padding.left + plotWidth / 2} y={chartHeight - 8} textAnchor="middle" fontSize="12" fill="#666" fontWeight="500">
          {chartType.charAt(0).toUpperCase() + chartType.slice(1)} ({data.length} days)
        </text>
      </svg>
    );
  };

  return (
    <div className="production-graph-page">
      <div className="graph-header">
        <h2>📈 Production Analytics</h2>
        <p>Visualize production trends and performance metrics</p>
      </div>

      {/* Filters */}
      <div className="graph-filters">
        <div className="filter-group">
          <label>Start Date</label>
          <input
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
          />
        </div>

        <div className="filter-group">
          <label>End Date</label>
          <input
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
          />
        </div>

        <button className="btn-load" onClick={fetchGraphData} disabled={loading}>
          {loading ? 'Loading...' : '📊 Load Data'}
        </button>

        <button 
          className="btn-refresh" 
          onClick={fetchGraphData} 
          disabled={loading}
          title="Refresh data to see latest updates"
        >
          🔄 Refresh
        </button>
      </div>

      {error && <div className="error-message">{error}</div>}

      {/* Chart Type Selector */}
      {graphData && graphData.length > 0 && (
        <div className="chart-type-selector">
          <button
            className={`chart-type-btn ${chartType === 'efficiency' ? 'active' : ''}`}
            onClick={() => setChartType('efficiency')}
          >
            📊 Efficiency
          </button>
          <button
            className={`chart-type-btn ${chartType === 'quality' ? 'active' : ''}`}
            onClick={() => setChartType('quality')}
          >
            ⭐ Quality
          </button>
          <button
            className={`chart-type-btn ${chartType === 'production' ? 'active' : ''}`}
            onClick={() => setChartType('production')}
          >
            📦 Production
          </button>
        </div>
      )}

      {/* Chart */}
      {graphData && graphData.length > 0 ? (
        <div className="chart-container">
          <div className="chart-wrapper">
            {renderChart()}
          </div>
          <p className="chart-info">
            📊 Showing {graphData.length} days of {chartType} data
          </p>
        </div>
      ) : !loading && (
        <div className="no-graph">
          <p>👉 Select a date range and click "Load Data" to view graphs</p>
        </div>
      )}

      {loading && (
        <div className="loading-state">
          <p>⏳ Loading data...</p>
        </div>
      )}
    </div>
  );
}
