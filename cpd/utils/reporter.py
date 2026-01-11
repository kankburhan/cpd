import json
import time
from typing import List, Dict

class Reporter:
    @staticmethod
    def generate_html_report(findings: List[Dict], output_path: str):
        """
        Generate a styled HTML report from the scan findings.
        """
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CPD Scan Report - {timestamp}</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px; background: #f0f2f5; color: #333; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                header {{ border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }}
                h1 {{ margin: 0; color: #1a1a1a; }}
                .meta {{ color: #666; margin-top: 5px; }}
                
                .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }}
                .card {{ padding: 20px; border-radius: 6px; text-align: center; color: white; }}
                .critical {{ background: #dc3545; }}
                .high {{ background: #fd7e14; }}
                .medium {{ background: #ffc107; color: #333; }}
                .low {{ background: #28a745; }}
                .count {{ font-size: 32px; font-weight: bold; display: block; }}
                .label {{ font-size: 14px; opacity: 0.9; }}
                
                .finding {{ border: 1px solid #e1e4e8; border-radius: 6px; margin-bottom: 20px; overflow: hidden; }}
                .finding-header {{ padding: 15px 20px; background: #f8f9fa; border-bottom: 1px solid #e1e4e8; display: flex; justify-content: space-between; align-items: center; }}
                .finding-title {{ font-weight: 600; font-size: 16px; }}
                .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; }}
                .badge.CRITICAL {{ background: #dc3545; }}
                .badge.HIGH {{ background: #fd7e14; }}
                .badge.MEDIUM {{ background: #ffc107; color: #333; }}
                .badge.LOW {{ background: #28a745; }}
                
                .finding-body {{ padding: 20px; }}
                .row {{ margin-bottom: 15px; }}
                .key {{ font-weight: 600; color: #555; display: inline-block; width: 120px; vertical-align: top; }}
                .val {{ display: inline-block; width: calc(100% - 130px); word-break: break-all; font-family: monospace; background: #f6f8fa; padding: 5px; border-radius: 4px; }}
                .details {{ white-space: pre-wrap; margin-top: 10px; background: #fff3cd; padding: 10px; border-radius: 4px; border: 1px solid #ffeeba; color: #856404; }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>CPD Scan Report</h1>
                    <div class="meta">Generated on {timestamp}</div>
                </header>
                
                <div class="summary">
                    <div class="card critical">
                        <span class="count">{severity_counts["CRITICAL"]}</span>
                        <span class="label">Critical</span>
                    </div>
                    <div class="card high">
                        <span class="count">{severity_counts["HIGH"]}</span>
                        <span class="label">High</span>
                    </div>
                    <div class="card medium">
                        <span class="count">{severity_counts["MEDIUM"]}</span>
                        <span class="label">Medium</span>
                    </div>
                    <div class="card low">
                        <span class="count">{severity_counts["LOW"]}</span>
                        <span class="label">Low</span>
                    </div>
                </div>
                
                <h2>Vulnerabilities ({len(findings)})</h2>
        """
        
        if not findings:
            html += "<p>No vulnerabilities found.</p>"
        
        for f in findings:
            sev = f.get("severity", "LOW").upper()
            sig = f.get("signature", {})
            html += f"""
                <div class="finding">
                    <div class="finding-header">
                        <span class="finding-title">{f.get('vulnerability', 'Unknown Vulnerability')}</span>
                        <span class="badge {sev}">{sev}</span>
                    </div>
                    <div class="finding-body">
                        <div class="row">
                            <span class="key">Target URL:</span>
                            <span class="val"><a href="{f.get('target_url', '#')}">{f.get('target_url', 'N/A')}</a></span>
                        </div>
                        <div class="row">
                            <span class="key">Verify URL:</span>
                            <span class="val"><a href="{f.get('verify_url', '#')}">{f.get('verify_url', 'N/A')}</a></span>
                        </div>
                         <div class="row">
                            <span class="key">Attack:</span>
                            <span class="val">{sig.get('name', 'N/A')} ({sig.get('header', 'N/A')}: {sig.get('value', 'N/A')})</span>
                        </div>
                        <div class="details">{f.get('details', '')}</div>
                    </div>
                </div>
            """
            
        html += """
            </div>
        </body>
        </html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html)
