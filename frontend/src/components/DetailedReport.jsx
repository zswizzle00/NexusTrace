import React from 'react';

const DetailedReport = ({ 
  data, 
  type,
  onExport,
  className = '' 
}) => {
  const formatDate = (date) => {
    return new Date(date).toLocaleString();
  };

  const renderReportContent = () => {
    switch (type) {
      case 'IP':
        return (
          <>
            <div className="space-y-4">
              <h4 className="text-lg font-semibold text-white">Geolocation</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-gray-400 text-sm">Country</p>
                  <p className="text-white font-medium">{data.country}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">City</p>
                  <p className="text-white font-medium">{data.city}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Region</p>
                  <p className="text-white font-medium">{data.region}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Coordinates</p>
                  <p className="text-white font-medium">{data.latitude}, {data.longitude}</p>
                </div>
              </div>
            </div>

            <div className="space-y-4 mt-6">
              <h4 className="text-lg font-semibold text-white">Network Details</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-gray-400 text-sm">ASN</p>
                  <p className="text-white font-medium">{data.asn}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Organization</p>
                  <p className="text-white font-medium">{data.organization}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Network Range</p>
                  <p className="text-white font-medium">{data.network_range}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Hostname</p>
                  <p className="text-white font-medium">{data.hostname || 'N/A'}</p>
                </div>
              </div>
            </div>

            {data.threats && data.threats.length > 0 && (
              <div className="space-y-4 mt-6">
                <h4 className="text-lg font-semibold text-white">Threat Intelligence</h4>
                <div className="space-y-2">
                  {data.threats.map((threat, index) => (
                    <div key={index} className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                      <p className="text-red-400 font-medium">{threat.type}</p>
                      <p className="text-gray-400 text-sm mt-1">{threat.description}</p>
                      {threat.severity && (
                        <div className="mt-2">
                          <p className="text-gray-400 text-sm">Severity: {threat.severity}</p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        );

      case 'Domain':
        return (
          <>
            <div className="space-y-4">
              <h4 className="text-lg font-semibold text-white">Registration Details</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-gray-400 text-sm">Registrar</p>
                  <p className="text-white font-medium">{data.registrar}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Creation Date</p>
                  <p className="text-white font-medium">{formatDate(data.creation_date)}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Expiration Date</p>
                  <p className="text-white font-medium">{formatDate(data.expiration_date)}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Last Updated</p>
                  <p className="text-white font-medium">{formatDate(data.updated_date)}</p>
                </div>
              </div>
            </div>

            <div className="space-y-4 mt-6">
              <h4 className="text-lg font-semibold text-white">DNS Records</h4>
              {Object.entries(data.dns_records || {}).map(([type, records]) => (
                <div key={type} className="space-y-2">
                  <p className="text-gray-400 text-sm">{type} Records</p>
                  <div className="space-y-2">
                    {records.map((record, index) => (
                      <div key={index} className="p-3 bg-gray-800/50 border border-gray-700 rounded-lg">
                        <p className="text-white font-medium">{record}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            {data.security_issues && data.security_issues.length > 0 && (
              <div className="space-y-4 mt-6">
                <h4 className="text-lg font-semibold text-white">Security Issues</h4>
                <div className="space-y-2">
                  {data.security_issues.map((issue, index) => (
                    <div key={index} className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                      <p className="text-red-400 font-medium">{issue.type}</p>
                      <p className="text-gray-400 text-sm mt-1">{issue.description}</p>
                      {issue.severity && (
                        <div className="mt-2">
                          <p className="text-gray-400 text-sm">Severity: {issue.severity}</p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        );

      case 'URL':
        return (
          <>
            <div className="space-y-4">
              <h4 className="text-lg font-semibold text-white">URL Information</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-gray-400 text-sm">Protocol</p>
                  <p className="text-white font-medium">{data.protocol}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Domain</p>
                  <p className="text-white font-medium">{data.domain}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Path</p>
                  <p className="text-white font-medium">{data.path}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Parameters</p>
                  <p className="text-white font-medium">
                    {data.parameters ? Object.keys(data.parameters).length : 0} parameters
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-4 mt-6">
              <h4 className="text-lg font-semibold text-white">Security Analysis</h4>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg">
                  <div>
                    <p className="text-gray-400 text-sm">Risk Score</p>
                    <p className="text-white font-medium">{data.risk_score}/100</p>
                  </div>
                  <div className={`px-3 py-1 rounded-full text-sm font-medium ${
                    data.risk_score < 30 ? 'bg-green-500/20 text-green-400' :
                    data.risk_score < 70 ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-red-500/20 text-red-400'
                  }`}>
                    {data.risk_score < 30 ? 'Safe' :
                     data.risk_score < 70 ? 'Suspicious' :
                     'Malicious'}
                  </div>
                </div>

                {data.security_issues && data.security_issues.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-gray-400 text-sm">Security Issues</p>
                    <div className="space-y-2">
                      {data.security_issues.map((issue, index) => (
                        <div key={index} className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                          <p className="text-red-400 font-medium">{issue.type}</p>
                          <p className="text-gray-400 text-sm mt-1">{issue.description}</p>
                          {issue.severity && (
                            <div className="mt-2">
                              <p className="text-gray-400 text-sm">Severity: {issue.severity}</p>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {data.redirects && data.redirects.length > 0 && (
              <div className="space-y-4 mt-6">
                <h4 className="text-lg font-semibold text-white">Redirect Chain</h4>
                <div className="space-y-2">
                  {data.redirects.map((redirect, index) => (
                    <div key={index} className="p-3 bg-gray-800/50 border border-gray-700 rounded-lg">
                      <p className="text-white font-medium">{redirect.url}</p>
                      <p className="text-gray-400 text-sm mt-1">Status: {redirect.status}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        );

      default:
        return null;
    }
  };

  return (
    <div className={`space-y-6 ${className}`}>
      <div className="flex items-center justify-between">
        <h3 className="text-xl font-semibold text-white">Detailed Report</h3>
        <button
          onClick={() => onExport(data)}
          className="btn btn-primary"
        >
          Export Report
        </button>
      </div>
      {renderReportContent()}
    </div>
  );
};

export default DetailedReport; 