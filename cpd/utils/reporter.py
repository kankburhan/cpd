import json
import time
import html
from typing import List, Dict
from urllib.parse import urlparse, quote

class Reporter:
    @staticmethod
    def generate_html_report(findings: List[Dict], output_path: str):
        """
        Generate a styled HTML report from the scan findings with PoC details.
        """
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CPD Scan Report - {timestamp}</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px; background: #f0f2f5; color: #333; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
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
                .card {{ cursor: pointer; transition: all 0.2s ease; }}
                .card:hover {{ transform: translateY(-5px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }}
                .card.active {{ transform: scale(1.02); ring: 2px solid white; }}
                .hidden {{ display: none !important; }}
                
                .finding {{ border: 1px solid #e1e4e8; border-radius: 6px; margin-bottom: 20px; overflow: hidden; }}
                .finding-header {{ padding: 15px 20px; background: #f8f9fa; border-bottom: 1px solid #e1e4e8; display: flex; justify-content: space-between; align-items: center; }}
                .finding-title {{ font-weight: 600; font-size: 16px; }}
                .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; }}
                .badge.CRITICAL {{ background: #dc3545; }}
                .badge.HIGH {{ background: #fd7e14; }}
                .badge.MEDIUM {{ background: #ffc107; color: #333; }}
                .badge.LOW {{ background: #28a745; }}
                
                .finding-body {{ padding: 20px; }}
                .section {{ margin-bottom: 20px; }}
                .section-title {{ font-weight: 600; color: #555; margin-bottom: 10px; font-size: 14px; text-transform: uppercase; }}
                
                .info-row {{ margin-bottom: 10px; }}
                .info-label {{ font-weight: 600; color: #555; display: inline-block; min-width: 120px; }}
                .info-value {{ font-family: monospace; background: #f6f8fa; padding: 3px 6px; border-radius: 4px; word-break: break-all; }}
                
                .details {{ white-space: pre-wrap; margin-top: 10px; background: #fff3cd; padding: 15px; border-radius: 4px; border: 1px solid #ffeeba; color: #856404; }}
                
                .evidence {{ background: #e7f3ff; padding: 15px; border-radius: 4px; border: 1px solid #b3d9ff; margin-top: 10px; }}
                .evidence-item {{ margin-bottom: 5px; font-family: monospace; font-size: 13px; }}
                
                .poc-section {{ background: #f0f0f0; padding: 15px; border-radius: 4px; margin-top: 10px; }}
                .poc-url {{ background: white; padding: 10px; border-radius: 4px; border: 1px solid #ddd; margin: 10px 0; word-break: break-all; font-family: monospace; font-size: 13px; }}
                .poc-curl {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 4px; margin: 10px 0; overflow-x: auto; font-family: 'Monaco', 'Courier New', monospace; font-size: 12px; position: relative; }}
                .copy-btn {{ position: absolute; top: 10px; right: 10px; background: #4CAF50; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; }}
                .copy-btn:hover {{ background: #45a049; }}
                
                .reflected {{ background: #fff5f5; padding: 15px; border-radius: 4px; border: 1px solid #ffcccc; margin-top: 10px; }}
                .reflected pre {{ margin: 10px 0; padding: 10px; background: white; border-radius: 4px; overflow-x: auto; font-size: 12px; }}
                
                a {{ color: #0366d6; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
                
                .footer {{ margin-top: 50px; padding-top: 30px; border-top: 2px solid #eee; text-align: center; }}
                .donate-section {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 8px; margin: 20px 0; }}
                .donate-title {{ font-size: 18px; font-weight: 600; margin-bottom: 15px; }}
                .donate-buttons {{ display: flex; gap: 15px; justify-content: center; align-items: center; flex-wrap: wrap; }}
                .donate-btn {{ background: white; color: #667eea; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 600; display: inline-flex; align-items: center; gap: 8px; transition: transform 0.2s; }}
                .donate-btn:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.2); }}
                .crypto-address {{ background: rgba(255,255,255,0.2); padding: 8px 12px; border-radius: 4px; font-family: monospace; font-size: 12px; margin-top: 10px; word-break: break-all; }}
                .footer-note {{ color: #666; font-size: 13px; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>🔍 CPD Security Scan Report</h1>
                    <div class="meta">Generated on {timestamp}</div>
                </header>
                
                <div class="summary">
                    <div class="card critical" onclick="filterFindings('CRITICAL')">
                        <span class="count">{severity_counts["CRITICAL"]}</span>
                        <span class="label">Critical</span>
                    </div>
                    <div class="card high" onclick="filterFindings('HIGH')">
                        <span class="count">{severity_counts["HIGH"]}</span>
                        <span class="label">High</span>
                    </div>
                    <div class="card medium" onclick="filterFindings('MEDIUM')">
                        <span class="count">{severity_counts["MEDIUM"]}</span>
                        <span class="label">Medium</span>
                    </div>
                    <div class="card low" onclick="filterFindings('LOW')">
                        <span class="count">{severity_counts["LOW"]}</span>
                        <span class="label">Low</span>
                    </div>
                </div>
                
                <h2>Vulnerabilities ({len(findings)})</h2>
        """
        
        if not findings:
            html_content += "<p>✅ No vulnerabilities found.</p>"
        
        for idx, f in enumerate(findings, 1):
            html_content += Reporter._render_finding(f, idx)
            
        html_content += """
                <div class="footer">
                    <div class="donate-section">
                        <div class="donate-title">💝 Support CPD Development</div>
                        <p style="margin: 10px 0; opacity: 0.95;">If this tool helped you find vulnerabilities, consider supporting its development!</p>
                        <div class="donate-buttons">
                            <a href="https://www.paypal.com/paypalme/kankburhan" target="_blank" class="donate-btn">
                                💳 Donate via PayPal
                            </a>
                            <button class="donate-btn" onclick="copyToClipboard('0x4618393bf4ddc50eb3e75df849b46aca0d0f8e3c')" style="border: none; cursor: pointer;">
                                💰 Copy Crypto Wallet
                            </button>
                        </div>
                        <div class="crypto-address">
                            <div style="font-size: 11px; opacity: 0.8; margin-bottom: 5px;">USDC Wallet Address:</div>
                            0x4618393bf4ddc50eb3e75df849b46aca0d0f8e3c
                        </div>
                    </div>
                    <div class="footer-note">
                        Generated by CPD - Cache Poisoning Detector<br>
                        <a href="https://github.com/kankburhan/cpd" target="_blank" style="color: #666;">github.com/kankburhan/cpd</a>
                    </div>
                </div>
            </div>
            <script>
                function copyToClipboard(text) {
                    navigator.clipboard.writeText(text).then(() => {
                        alert('Copied to clipboard!');
                    });
                }

                function filterFindings(severity) {
                    const cards = document.querySelectorAll('.card');
                    const findings = document.querySelectorAll('.finding');
                    
                    // Toggle active state on cards
                    cards.forEach(card => {
                        if (card.classList.contains(severity.toLowerCase())) {
                            card.classList.toggle('active');
                            // If we're turning off the active state, we want to show all
                            if (!card.classList.contains('active')) {
                                severity = 'ALL';
                            }
                        } else {
                            card.classList.remove('active');
                        }
                    });

                    // Filter findings
                    findings.forEach(finding => {
                        const badge = finding.querySelector('.badge');
                        if (severity === 'ALL' || badge.classList.contains(severity)) {
                            finding.classList.remove('hidden');
                        } else {
                            finding.classList.add('hidden');
                        }
                    });

                    // Update header text based on visible count
                    const visibleCount = document.querySelectorAll('.finding:not(.hidden)').length;
                    const headerText = document.querySelector('h2');
                    headerText.textContent = `Vulnerabilities (${visibleCount})`;
                }
            </script>
        </body>
        </html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    @staticmethod
    def _render_finding(f: Dict, idx: int) -> str:
        """Render a single finding as HTML."""
        sev = f.get("severity", "LOW").upper()
        sig = f.get("signature", {})
        vuln_type = html.escape(f.get('vulnerability', 'Unknown Vulnerability'))
        
        # Generate PoC details
        poc_url = Reporter._generate_poc_url(f)
        curl_cmd = Reporter._generate_curl_command(f)
        
        finding_html = f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="finding-title">#{idx} - {vuln_type}</span>
                    <span class="badge {sev}">{sev}</span>
                </div>
                <div class="finding-body">
        """
        
        # Basic Info Section
        finding_html += """
                    <div class="section">
                        <div class="section-title">📋 Basic Information</div>
        """
        
        if f.get('url'):
            finding_html += f"""
                        <div class="info-row">
                            <span class="info-label">Base URL:</span>
                            <span class="info-value"><a href="{html.escape(f['url'])}" target="_blank">{html.escape(f['url'])}</a></span>
                        </div>
            """
        
        if f.get('target_url'):
            finding_html += f"""
                        <div class="info-row">
                            <span class="info-label">Target URL:</span>
                            <span class="info-value"><a href="{html.escape(f['target_url'])}" target="_blank">{html.escape(f['target_url'])}</a></span>
                        </div>
            """
        
        if sig.get('name'):
            finding_html += f"""
                        <div class="info-row">
                            <span class="info-label">Signature:</span>
                            <span class="info-value">{html.escape(sig.get('name', 'N/A'))}</span>
                        </div>
            """
        
        finding_html += """
                    </div>
        """
        
        # Details
        if f.get('details'):
            finding_html += f"""
                    <div class="section">
                        <div class="section-title">📝 Details</div>
                        <div class="details">{html.escape(f['details'])}</div>
                    </div>
            """
        
        # Evidence Section
        evidence_html = Reporter._render_evidence(f)
        if evidence_html:
            finding_html += evidence_html
        
        # PoC Section
        if poc_url or curl_cmd:
            finding_html += """
                    <div class="section">
                        <div class="section-title">🎯 Proof of Concept</div>
                        <div class="poc-section">
            """
            
            if poc_url:
                finding_html += f"""
                            <p><strong>Vulnerable URL:</strong></p>
                            <div class="poc-url">
                                <a href="{html.escape(poc_url)}" target="_blank">{html.escape(poc_url)}</a>
                            </div>
                """
            
            if curl_cmd:
                curl_escaped = html.escape(curl_cmd)
                # Escape backticks for JavaScript
                curl_for_js = curl_escaped.replace('`', '\\`')
                finding_html += f"""
                            <p><strong>Reproduce with curl:</strong></p>
                            <div class="poc-curl">
                                <button class="copy-btn" onclick="copyToClipboard(`{curl_for_js}`)">Copy</button>
                                {curl_escaped}
                            </div>
                """
            
            finding_html += """
                        </div>
                    </div>
            """
        
        # Reflected Content
        reflected_html = Reporter._render_reflected_content(f)
        if reflected_html:
            finding_html += reflected_html
        
        finding_html += """
                </div>
            </div>
        """
        
        return finding_html
    
    @staticmethod
    def _render_evidence(f: Dict) -> str:
        """Render evidence section including cache headers and variant URLs."""
        evidence_items = []
        
        # Cache headers evidence
        if f.get('evidence'):
            evidence_list = f['evidence'] if isinstance(f['evidence'], list) else [f['evidence']]
            for ev in evidence_list:
                evidence_items.append(f"<div class='evidence-item'>🔍 {html.escape(str(ev))}</div>")
        
        # Variant URL for normalization vulnerabilities
        if f.get('variant_url'):
            evidence_items.append(f"<div class='evidence-item'>🔗 <strong>Variant URL:</strong> <a href='{html.escape(f['variant_url'])}' target='_blank'>{html.escape(f['variant_url'])}</a></div>")
        
        if f.get('original_url') and f.get('variant_url'):
            evidence_items.append(f"<div class='evidence-item'>🔗 <strong>Original URL:</strong> <a href='{html.escape(f['original_url'])}' target='_blank'>{html.escape(f['original_url'])}</a></div>")
        
        if not evidence_items:
            return ""
        
        return f"""
                    <div class="section">
                        <div class="section-title">🔬 Evidence</div>
                        <div class="evidence">
                            {''.join(evidence_items)}
                        </div>
                    </div>
        """
    
    @staticmethod
    def _render_reflected_content(f: Dict) -> str:
        """Render reflected content section if available."""
        if not f.get('reflected_in') and not f.get('reflection_context'):
            return ""
        
        reflected_html = """
                    <div class="section">
                        <div class="section-title">⚠️ Reflected Content</div>
                        <div class="reflected">
        """
        
        if f.get('reflected_in'):
            reflected_html += f"<p><strong>Reflected in:</strong> {html.escape(f['reflected_in'])}</p>"
        
        if f.get('reflection_context'):
            reflected_html += f"""
                            <p><strong>Context:</strong></p>
                            <pre>{html.escape(f['reflection_context'][:500])}{'...' if len(f.get('reflection_context', '')) > 500 else ''}</pre>
            """
        
        if f.get('payload'):
            reflected_html += f"<p><strong>Payload:</strong> <code>{html.escape(str(f['payload']))}</code></p>"
        
        reflected_html += """
                        </div>
                    </div>
        """
        
        return reflected_html
    
    @staticmethod
    def _generate_poc_url(f: Dict) -> str:
        """Generate PoC URL based on vulnerability type."""
        vuln_type = f.get('vulnerability', '')
        
        # For normalization vulnerabilities, use variant URL
        if vuln_type == 'CacheKeyNormalization' and f.get('variant_url'):
            return f['variant_url']
        
        # For other vulnerabilities, use target_url or verify_url
        return f.get('target_url') or f.get('verify_url') or f.get('url') or ''
    
    @staticmethod
    def _generate_curl_command(f: Dict) -> str:
        """Generate curl command to reproduce the vulnerability."""
        url = Reporter._generate_poc_url(f)
        if not url:
            return ""
        
        sig = f.get('signature', {})
        cmd_parts = ['curl', '-i', '-s']
        
        # Add malicious header if present
        if sig.get('header') and sig.get('value'):
            header_value = str(sig['value']).replace("'", "'\"'\"'")  # Escape single quotes
            cmd_parts.append(f"-H '{sig['header']}: {header_value}'")
        
        # Add URL
        cmd_parts.append(f"'{url}'")
        
        return ' '.join(cmd_parts)

