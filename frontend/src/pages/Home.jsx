import React from 'react';
import { Link } from 'react-router-dom';

const Home = () => {
  return (
    <div className="flex flex-col items-center justify-center min-h-[80vh] text-center px-4">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl md:text-5xl font-bold mb-6 bg-gradient-to-r from-blue-400 to-blue-600 bg-clip-text text-transparent">
          Welcome to NexusTrace
        </h1>
        <p className="text-lg md:text-xl text-gray-300 mb-8">
          Your comprehensive OSINT and threat intelligence platform for analyzing IP addresses, domains, and URLs.
        </p>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
          {/* IP Analysis Card */}
          <div className="bg-[#232946] border border-[#374151] rounded-xl p-6 transition-all duration-300 hover:shadow-lg hover:border-blue-500 hover:-translate-y-1">
            <div className="flex flex-col items-center">
              <div className="w-12 h-12 mb-4 text-blue-400 group-hover:text-blue-300 transition-colors">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <h3 className="text-xl font-semibold mb-2 text-white">IP Analysis</h3>
              <p className="text-gray-400">Comprehensive analysis of IP addresses including geolocation, reputation, and threat intelligence.</p>
            </div>
          </div>
          
          {/* Domain Analysis Card */}
          <div className="bg-[#232946] border border-[#374151] rounded-xl p-6 transition-all duration-300 hover:shadow-lg hover:border-blue-500 hover:-translate-y-1">
            <div className="flex flex-col items-center">
              <div className="w-12 h-12 mb-4 text-blue-400 group-hover:text-blue-300 transition-colors">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                </svg>
              </div>
              <h3 className="text-xl font-semibold mb-2 text-white">Domain Analysis</h3>
              <p className="text-gray-400">In-depth domain investigation including WHOIS data, DNS records, and security metrics.</p>
            </div>
          </div>
          
          {/* URL Analysis Card */}
          <div className="bg-[#232946] border border-[#374151] rounded-xl p-6 transition-all duration-300 hover:shadow-lg hover:border-blue-500 hover:-translate-y-1">
            <div className="flex flex-col items-center">
              <div className="w-12 h-12 mb-4 text-blue-400 group-hover:text-blue-300 transition-colors">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
              </div>
              <h3 className="text-xl font-semibold mb-2 text-white">URL Analysis</h3>
              <p className="text-gray-400">Detailed URL scanning for malicious content, redirects, and security vulnerabilities.</p>
            </div>
          </div>
        </div>
        
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link to="/ip" className="inline-flex items-center gap-2 px-6 py-3 bg-blue-500 text-white rounded-lg font-semibold hover:bg-blue-600 transition-colors duration-200">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Start IP Analysis
          </Link>
          <Link to="/domain" className="inline-flex items-center gap-2 px-6 py-3 bg-blue-500 text-white rounded-lg font-semibold hover:bg-blue-600 transition-colors duration-200">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
            </svg>
            Start Domain Analysis
          </Link>
          <Link to="/url" className="inline-flex items-center gap-2 px-6 py-3 bg-blue-500 text-white rounded-lg font-semibold hover:bg-blue-600 transition-colors duration-200">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
            Start URL Analysis
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Home; 