import React, { useState, useEffect } from 'react';
import '../styles/ProductionReport.css';

export default function ProductionReport() {
  const [reportData, setReportData] = useState(null);
  const [floorId, setFloorId] = useState(null);
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Get available floors
  const [floors, setFloors] = useState([]);

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

    // Initialize dates to today
    const today = new Date();
    const thirtyDaysAgo = new Date(today.getTime() - (30 * 24 * 60 * 60 * 1000));
    
    setStartDate(thirtyDaysAgo.toISOString().split('T')[0]);
    setEndDate(today.toISOString().split('T')[0]);
  }, []);

  const fetchReport = async () => {
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
        throw new Error(`Failed to fetch report: ${response.statusText}`);
      }

      const data = await response.json();
      setReportData(data);
    } catch (err) {
      console.error('Error fetching report:', err);
      setError(err.message || 'Failed to load report');
    } finally {
      setLoading(false);
    }
  };

  const downloadCSV = () => {
    if (!reportData) return;

    let csv = 'Production Report\n';
    csv += `Date Range: ${startDate} to ${endDate}\n`;
    csv += `Generated: ${new Date().toLocaleString()}\n\n`;

    // Summary
    csv += 'SUMMARY\n';
    csv += `Total Records,${reportData.summary.totalRecords}\n`;
    csv += `Total Produced,${reportData.summary.totalProduced}\n`;
    csv += `Total Target,${reportData.summary.totalTarget}\n`;
    csv += `Overall Efficiency,${reportData.summary.overallEfficiency}%\n`;
    if (reportData.summary.avgQualityRate !== null) {
      csv += `Avg Quality Rate,${reportData.summary.avgQualityRate}%\n`;
    }
    csv += '\n';

    // Detailed records
    csv += 'DETAILED RECORDS\n';
    csv += 'Date,Shift,Workers,Target,Produced,Efficiency,Quality,Recorded By,Notes\n';
    
    reportData.records.forEach(record => {
      const notes = record.notes ? `"${record.notes}"` : '';
      csv += `${new Date(record.date).toLocaleDateString()},${record.shiftName},${record.workersCount},${record.target},${record.produced},${record.efficiency}%,${record.qualityRate ? record.qualityRate.toFixed(1) : 'N/A'}%,${record.recordedBy},${notes}\n`;
    });

    // Download
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv));
    element.setAttribute('download', `production-report-${startDate}-to-${endDate}.csv`);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const downloadPDF = () => {
    if (!reportData) return;

    // Create a new document
    const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Production Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
    h1 { color: #1B4332; border-bottom: 2px solid #1B4332; padding-bottom: 10px; }
    h2 { color: #1B4332; margin-top: 20px; font-size: 14px; border-bottom: 1px solid #D8E2DC; padding-bottom: 5px; }
    .header-info { margin-bottom: 20px; font-size: 12px; color: #666; }
    .summary { margin: 20px 0; display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }
    .summary-card { border: 1px solid #D8E2DC; padding: 10px; border-radius: 5px; background: #F9F9F9; }
    .summary-card strong { color: #1B4332; display: block; margin-bottom: 5px; }
    .summary-card span { font-size: 18px; font-weight: bold; color: #10B981; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 11px; }
    th { background: #1B4332; color: white; padding: 8px; text-align: left; font-weight: bold; }
    td { border-bottom: 1px solid #D8E2DC; padding: 8px; }
    tr:nth-child(even) { background: #F9F9F9; }
    .footer { margin-top: 30px; font-size: 10px; color: #999; border-top: 1px solid #D8E2DC; padding-top: 10px; }
  </style>
</head>
<body>
  <h1>📊 Production Report</h1>
  
  <div class="header-info">
    <p><strong>Date Range:</strong> ${startDate} to ${endDate}</p>
    <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
  </div>

  <h2>Summary</h2>
  <div class="summary">
    <div class="summary-card">
      <strong>Total Records</strong>
      <span>${reportData.summary.totalRecords}</span>
    </div>
    <div class="summary-card">
      <strong>Total Produced</strong>
      <span>${reportData.summary.totalProduced.toLocaleString()} units</span>
    </div>
    <div class="summary-card">
      <strong>Total Target</strong>
      <span>${reportData.summary.totalTarget.toLocaleString()} units</span>
    </div>
    <div class="summary-card">
      <strong>Overall Efficiency</strong>
      <span>${reportData.summary.overallEfficiency}%</span>
    </div>
    ${reportData.summary.avgQualityRate !== null ? `
    <div class="summary-card">
      <strong>Avg Quality Rate</strong>
      <span>${reportData.summary.avgQualityRate}%</span>
    </div>
    ` : ''}
  </div>

  <h2>Detailed Records</h2>
  <table>
    <thead>
      <tr>
        <th>Date</th>
        <th>Shift</th>
        <th>Workers</th>
        <th>Target</th>
        <th>Produced</th>
        <th>Efficiency</th>
        <th>Quality</th>
        <th>Recorded By</th>
      </tr>
    </thead>
    <tbody>
      ${reportData.records.map(record => `
        <tr>
          <td>${new Date(record.date).toLocaleDateString()}</td>
          <td>${record.shiftName}</td>
          <td>${record.workersCount}</td>
          <td>${record.target}</td>
          <td>${record.produced}</td>
          <td>${record.efficiency}%</td>
          <td>${record.qualityRate ? record.qualityRate.toFixed(1) : 'N/A'}%</td>
          <td>${record.recordedBy}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <div class="footer">
    <p>This report was automatically generated from the Motion Production Management System.</p>
  </div>
</body>
</html>
    `;

    // Convert HTML to PDF using html2pdf library approach
    // For now, we'll create a printable HTML document
    const printWindow = window.open('', '_blank');
    printWindow.document.write(html);
    printWindow.document.close();
    
    // Trigger print dialog which allows saving as PDF
    setTimeout(() => {
      printWindow.print();
    }, 250);
  };

  return (
    <div className="production-report-page">
      <div className="report-header">
        <h2>📊 Production Report</h2>
        <p>View and analyze production data</p>
      </div>

      {/* Report Filters */}
      <div className="report-filters">
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

        <button className="btn-generate" onClick={fetchReport} disabled={loading}>
          {loading ? 'Generating...' : '🔍 Generate Report'}
        </button>

        <button 
          className="btn-refresh" 
          onClick={fetchReport} 
          disabled={loading}
          title="Refresh data to see latest updates"
        >
          🔄 Refresh
        </button>
      </div>

      {error && <div className="error-message">{error}</div>}

      {/* Report Summary */}
      {reportData && (
        <>
          <div className="report-summary">
            <div className="summary-card">
              <h4>Total Records</h4>
              <p className="summary-value">{reportData.summary.totalRecords}</p>
            </div>
            <div className="summary-card">
              <h4>Total Produced</h4>
              <p className="summary-value">{reportData.summary.totalProduced.toLocaleString()} units</p>
            </div>
            <div className="summary-card">
              <h4>Total Target</h4>
              <p className="summary-value">{reportData.summary.totalTarget.toLocaleString()} units</p>
            </div>
            <div className="summary-card">
              <h4>Overall Efficiency</h4>
              <p className={`summary-value ${reportData.summary.overallEfficiency >= 90 ? 'excellent' : 'good'}`}>
                {reportData.summary.overallEfficiency}%
              </p>
            </div>
            {reportData.summary.avgQualityRate !== null && (
              <div className="summary-card">
                <h4>Avg Quality Rate</h4>
                <p className={`summary-value ${reportData.summary.avgQualityRate >= 98 ? 'excellent' : 'good'}`}>
                  {reportData.summary.avgQualityRate}%
                </p>
              </div>
            )}
          </div>

          {/* Download Buttons */}
          <div className="report-actions">
            <button className="btn-download" onClick={downloadCSV}>
              📥 Download as CSV
            </button>
            <button className="btn-download pdf" onClick={downloadPDF}>
              📄 Download as PDF
            </button>
          </div>

          {/* Detailed Records Table */}
          <div className="report-details">
            <h3>Detailed Records</h3>
            {reportData.records.length === 0 ? (
              <p className="no-data">No production records found for the selected date range.</p>
            ) : (
              <div className="table-wrapper">
                <table className="report-table">
                  <thead>
                    <tr>
                      <th>Date</th>
                      <th>Shift</th>
                      <th>Workers</th>
                      <th>Target</th>
                      <th>Produced</th>
                      <th>Efficiency</th>
                      <th>Quality</th>
                      <th>Recorded By</th>
                      <th>Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportData.records.map((record, idx) => (
                      <tr key={idx}>
                        <td>{new Date(record.date).toLocaleDateString()}</td>
                        <td>{record.shiftName}</td>
                        <td className="center">{record.workersCount}</td>
                        <td className="center">{record.target}</td>
                        <td className="center">{record.produced}</td>
                        <td className="center">
                          <span className={`badge ${record.efficiency >= 95 ? 'excellent' : record.efficiency >= 80 ? 'good' : 'fair'}`}>
                            {record.efficiency}%
                          </span>
                        </td>
                        <td className="center">
                          <span className={`badge ${record.qualityRate >= 98 ? 'excellent' : record.qualityRate >= 95 ? 'good' : 'fair'}`}>
                            {record.qualityRate ? record.qualityRate.toFixed(1) : 'N/A'}%
                          </span>
                        </td>
                        <td>{record.recordedBy}</td>
                        <td className="notes">{record.notes || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {!reportData && !loading && (
        <div className="no-report">
          <p>👉 Select a date range and click "Generate Report" to view production data</p>
        </div>
      )}
    </div>
  );
}
