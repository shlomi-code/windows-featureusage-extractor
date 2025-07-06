#!/usr/bin/env python3
"""
HTML Exporter for Windows FeatureUsage Data

This module provides functionality to export FeatureUsage extraction results
to HTML format with interactive tables, search functionality, and charts.
"""

from datetime import datetime
from typing import Dict, Any, Optional, List


class HTMLExporter:
    """Handles HTML export functionality for FeatureUsage extraction results."""
    
    def __init__(self):
        """Initialize the HTML exporter."""
        pass
    
    def export_results(self, results: Dict[str, Any], filename: Optional[str] = None) -> str:
        """
        Export extraction results to an HTML file with tables and search functionality.
        
        Args:
            results: Dictionary containing the extraction results
            filename: Optional filename for the output file
            
        Returns:
            Filename of the saved HTML file or empty string if failed
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"featureusage_extraction_{timestamp}.html"
        
        try:
            html_content = self._generate_html_content(results)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"\nHTML report saved to: {filename}")
            return filename
        except Exception as e:
            print(f"Error saving HTML report: {e}")
            return ""
    
    def _generate_html_content(self, results: Dict[str, Any]) -> str:
        """
        Generate the complete HTML content for the report.
        
        Args:
            results: Dictionary containing the extraction results
            
        Returns:
            Complete HTML content as a string
        """
        # Generate chart data
        chart_html = self._generate_chart_html(results)
        
        # Generate table sections
        table_sections = self._generate_table_sections(results)
        
        # Combine everything into the final HTML
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Windows FeatureUsage Extraction Report</title>
    {self._get_css_styles()}
</head>
<body>
    <h1>Windows FeatureUsage Extraction Report</h1>
    <p><strong>Extraction time:</strong> {results.get("extraction_time", "")}</p>
    <p><strong>Current User:</strong> {results.get("current_user_sid", "")}</p>
    <p><strong>User SID:</strong> {results.get("full_user_sid", "")}</p>
    <p><strong>Total entries:</strong> {results.get("total_entries", 0)}</p>
    <p><strong>Summary:</strong> {results.get("summary", {})}</p>
    
    <!-- Chart container -->
    <div class="chart-container">
        <div class="chart-title">📊 Artifact Distribution</div>
        {chart_html}
    </div>
    
    <!-- Search functionality -->
    <div class="search-container">
        <h3>🔍 Search Data</h3>
        <input type="text" id="searchInput" class="search-input" placeholder="Search for applications, timestamps, or any data...">
        <button onclick="searchData()" class="search-button">Search</button>
        <button onclick="clearSearch()" class="clear-button">Clear</button>
        <div class="stats" id="searchStats"></div>
        <div id="noResultsMessage" class="no-results" style="display:none;">No results found for your search. Try a shorter or different search term.</div>
    </div>
    
    {self._get_javascript_code()}
    
    {table_sections}
    
</body>
</html>'''
        
        return html_content
    
    def _generate_chart_html(self, results: Dict[str, Any]) -> str:
        """
        Generate the chart HTML for artifact distribution.
        
        Args:
            results: Dictionary containing the extraction results
            
        Returns:
            Chart HTML as a string
        """
        # Prepare chart data
        chart_data = [
            ("AppSwitched", len(results.get("appswitched_data", []))),
            ("ShowJumpView", len(results.get("showjumpview_data", []))),
            ("AppBadgeUpdated", len(results.get("appbadgeupdated_data", []))),
            ("AppLaunch", len(results.get("applaunch_data", []))),
            ("StartMenu", len(results.get("startmenu_data", []))),
            ("Search", len(results.get("search_data", [])))
        ]
        
        # Filter out zero counts and sort by count
        chart_data = [(name, count) for name, count in chart_data if count > 0]
        chart_data.sort(key=lambda x: x[1], reverse=True)
        
        # Generate chart HTML
        if chart_data:
            max_count = max(count for _, count in chart_data)
            chart_html = ""
            for name, count in chart_data:
                percentage = (count / max_count) * 100 if max_count > 0 else 0
                chart_html += f'''
                <div class="chart-bar-container">
                    <div class="chart-label">{name}</div>
                    <div class="chart-bar-wrapper">
                        <div class="chart-bar" style="width: {percentage}%;">
                            <span class="chart-value">{count}</span>
                        </div>
                    </div>
                    <div class="chart-max-label">{max_count}</div>
                </div>'''
        else:
            chart_html = '<p style="text-align:center;color:#6c757d;font-style:italic;">No data available for chart</p>'
        
        return chart_html
    
    def _generate_table_sections(self, results: Dict[str, Any]) -> str:
        """
        Generate all table sections for the HTML report.
        
        Args:
            results: Dictionary containing the extraction results
            
        Returns:
            All table sections HTML as a string
        """
        table_sections = ""
        
        # Define table configurations
        table_configs = [
            ("featureusage_data", "FeatureUsage Data", "featureusage-table"),
            ("appswitched_data", "AppSwitched Data", "appswitched-table"),
            ("showjumpview_data", "ShowJumpView Data", "showjumpview-table"),
            ("appbadgeupdated_data", "AppBadgeUpdated Data", "appbadgeupdated-table"),
            ("applaunch_data", "AppLaunch Data", "applaunch-table")
        ]
        
        for data_key, title, table_id in table_configs:
            data = results.get(data_key, [])
            table_sections += self._dicts_to_html_table(data, title, table_id)
        
        return table_sections
    
    def _dicts_to_html_table(self, dicts: List[Dict[str, Any]], title: str, table_id: str) -> str:
        """
        Convert a list of dictionaries to an HTML table.
        
        Args:
            dicts: List of dictionaries to convert
            title: Title for the table section
            table_id: Unique ID for the table
            
        Returns:
            HTML table as a string
        """
        if not dicts:
            return f'''
            <div class="table-section">
                <div class="table-header" onclick="toggleTable('{table_id}')">
                    <span class="toggle-icon">▶</span> {title} <span class="entry-count">(No data found)</span>
                </div>
                <div id="{table_id}-content" class="table-content collapsed">
                    <p>No data found.</p>
                </div>
            </div>'''
        
        headers = sorted({k for d in dicts for k in d.keys()})
        table_html = f'''
            <div class="table-section">
                <div class="table-header" onclick="toggleTable('{table_id}')">
                    <span class="toggle-icon">▶</span> {title} <span class="entry-count">({len(dicts)} entries)</span>
                </div>
                <div id="{table_id}-content" class="table-content collapsed">
                    <div class="table-wrapper">
                        <table id="{table_id}" border="1" cellspacing="0" cellpadding="4" class="data-table">
                            <tr>'''
        
        for h in headers:
            table_html += f'<th>{h}</th>'
        table_html += '</tr>'
        
        for d in dicts:
            table_html += '<tr>'
            for h in headers:
                value = d.get(h, "")
                table_html += f'<td>{value}</td>'
            table_html += '</tr>'
        
        table_html += '''
                        </table>
                    </div>
                </div>
            </div>'''
        return table_html
    
    def _get_css_styles(self) -> str:
        """
        Get the CSS styles for the HTML report.
        
        Returns:
            CSS styles as a string
        """
        return '''<style>
        body { font-family: sans-serif; margin: 20px; }
        table { border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 8px 12px; text-align: left; border: 1px solid #ddd; }
        th { background: #f2f2f2; font-weight: bold; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f5f5f5; }
        
        .search-container { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        .search-input { width: 300px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .search-button { padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 10px; }
        .search-button:hover { background: #0056b3; }
        .clear-button { padding: 8px 16px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 10px; }
        .clear-button:hover { background: #545b62; }
        .stats { margin: 10px 0; font-size: 14px; color: #666; }
        .hidden { display: none; }
        .highlight { background-color: #fff3cd; font-weight: bold; }
        .no-results { color: #dc3545; font-style: italic; padding: 10px; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px; margin: 10px 0; }
        
        .table-section { margin: 15px 0; border: 1px solid #ddd; border-radius: 5px; overflow: hidden; }
        .table-header { background: #e9ecef; padding: 12px 15px; cursor: pointer; font-weight: bold; font-size: 16px; border-bottom: 1px solid #ddd; transition: background-color 0.2s; }
        .table-header:hover { background: #d1ecf1; }
        .toggle-icon { display: inline-block; margin-right: 10px; font-size: 12px; transition: transform 0.2s; }
        .entry-count { float: right; font-size: 14px; color: #6c757d; font-weight: normal; }
        .table-content { padding: 15px; background: white; transition: all 0.3s ease-out; overflow: hidden; }
        .table-content.collapsed { max-height: 0; padding: 0 15px; opacity: 0; }
        .table-content.expanded { max-height: 2000px; opacity: 1; }
        
        .table-wrapper { overflow-x: scroll; overflow-y: auto; max-width: 100%; max-height: 400px; }
        .data-table { min-width: 1200px; }
        
        .chart-container { margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; border: 1px solid #dee2e6; }
        .chart-title { font-size: 18px; font-weight: bold; margin-bottom: 15px; color: #495057; }
        .chart-bar-container { margin: 10px 0; display: flex; align-items: center; }
        .chart-label { width: 200px; font-weight: bold; color: #495057; margin-right: 15px; }
        .chart-bar-wrapper { flex: 1; background: #e9ecef; border-radius: 4px; height: 25px; position: relative; overflow: hidden; }
        .chart-bar { height: 100%; background: linear-gradient(90deg, #007bff, #0056b3); border-radius: 4px; transition: width 0.5s ease-in-out; position: relative; }
        .chart-value { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); color: white; font-weight: bold; font-size: 12px; }
        .chart-max-label { width: 60px; text-align: right; font-size: 12px; color: #6c757d; margin-left: 10px; }
    </style>'''
    
    def _get_javascript_code(self) -> str:
        """
        Get the JavaScript code for the HTML report.
        
        Returns:
            JavaScript code as a string
        """
        return '''<script>
        function toggleTable(tableId) {
            const content = document.getElementById(tableId + "-content");
            const header = content.previousElementSibling;
            const icon = header.querySelector(".toggle-icon");
            
            if (content.classList.contains("collapsed")) {
                content.classList.remove("collapsed");
                content.classList.add("expanded");
                icon.textContent = "▼";
            } else {
                content.classList.remove("expanded");
                content.classList.add("collapsed");
                icon.textContent = "▶";
            }
        }
        
        function searchData() {
            const searchTerm = document.getElementById("searchInput").value.toLowerCase().trim();
            const tables = document.querySelectorAll(".data-table");
            const noResultsDiv = document.getElementById("noResultsMessage");
            let totalMatches = 0;
            let totalRows = 0;
            let tablesWithMatches = 0;
            
            noResultsDiv.style.display = "none";
            
            if (!searchTerm) {
                clearSearch();
                return;
            }
            
            tables.forEach(table => {
                const rows = table.querySelectorAll("tr");
                let tableMatches = 0;
                
                rows.forEach((row, index) => {
                    if (index === 0) {
                        row.style.display = "";
                        return;
                    }
                    totalRows++;
                    const cells = row.querySelectorAll("td");
                    let rowMatch = false;
                    
                    cells.forEach(cell => {
                        const cellText = cell.textContent.toLowerCase();
                        if (cellText.includes(searchTerm)) {
                            rowMatch = true;
                            cell.classList.add("highlight");
                        } else {
                            cell.classList.remove("highlight");
                        }
                    });
                    
                    if (rowMatch) {
                        row.style.display = "";
                        tableMatches++;
                        totalMatches++;
                    } else {
                        row.style.display = "none";
                    }
                });
                
                const tableSection = table.closest(".table-section");
                const tableContent = tableSection.querySelector(".table-content");
                
                if (tableMatches > 0) {
                    tablesWithMatches++;
                    tableSection.style.display = "block";
                    if (tableContent.classList.contains("collapsed")) {
                        toggleTable(table.id);
                    }
                } else {
                    tableSection.style.display = "none";
                }
            });
            
            const statsDiv = document.getElementById("searchStats");
            if (searchTerm) {
                if (totalMatches > 0) {
                    statsDiv.innerHTML = `Found ${totalMatches} matches out of ${totalRows} total entries in ${tablesWithMatches} table(s)`;
                } else {
                    statsDiv.innerHTML = `No matches found in any table`;
                    noResultsDiv.style.display = "block";
                }
            } else {
                statsDiv.innerHTML = "";
            }
        }
        
        function clearSearch() {
            document.getElementById("searchInput").value = "";
            document.getElementById("searchStats").innerHTML = "";
            document.getElementById("noResultsMessage").style.display = "none";
            const tables = document.querySelectorAll(".data-table");
            tables.forEach(table => {
                const rows = table.querySelectorAll("tr");
                rows.forEach(row => {
                    row.style.display = "";
                    const cells = row.querySelectorAll("td");
                    cells.forEach(cell => cell.classList.remove("highlight"));
                });
                const tableSection = table.closest(".table-section");
                tableSection.style.display = "block";
            });
        }
        
        document.getElementById("searchInput").addEventListener("keypress", function(event) {
            if (event.key === "Enter") {
                searchData();
            }
        });
        
        let searchTimeout;
        document.getElementById("searchInput").addEventListener("input", function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(searchData, 300);
        });
    </script>'''
    
    def validate_results(self, results: Dict[str, Any]) -> bool:
        """
        Validate that the results dictionary contains required fields.
        
        Args:
            results: Dictionary containing the extraction results
            
        Returns:
            True if results are valid, False otherwise
        """
        required_fields = [
            "extraction_time",
            "current_user_sid",
            "featureusage_data",
            "appswitched_data",
            "showjumpview_data",
            "appbadgeupdated_data",
            "applaunch_data",
            "startmenu_data",
            "search_data"
        ]
        
        for field in required_fields:
            if field not in results:
                print(f"Warning: Missing required field '{field}' in results")
                return False
        
        return True
    
    def get_export_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary of the export data.
        
        Args:
            results: Dictionary containing the extraction results
            
        Returns:
            Dictionary containing export summary information
        """
        summary = {
            "export_time": datetime.now().isoformat(),
            "total_entries": results.get("total_entries", 0),
            "data_sources": {
                "appswitched_entries": len(results.get("appswitched_data", [])),
                "showjumpview_entries": len(results.get("showjumpview_data", [])),
                "appbadgeupdated_entries": len(results.get("appbadgeupdated_data", [])),
                "applaunch_entries": len(results.get("applaunch_data", [])),
                "startmenu_entries": len(results.get("startmenu_data", [])),
                "search_entries": len(results.get("search_data", []))
            },
            "extraction_info": {
                "extraction_time": results.get("extraction_time", ""),
                "current_user_sid": results.get("current_user_sid", "")
            }
        }
        
        return summary 