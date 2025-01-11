import json
from collections import Counter, defaultdict
from datetime import datetime

def parse_log_entry(line):
    """Function to parse a line of log"""
    try:
        _, log_data = line.split(" - INFO - Technique Execution ")
        return json.loads(log_data)
    except:
        return None

def read_log_file(file_path):
    """Function to open and read contents of the app log file"""
    with open(file_path, 'r') as file:
        return file.readlines()

def analyze_log(log_lines):
    """Function to analyze app logs to generate metrics"""
    executions = defaultdict(dict)
    for line in log_lines:
        entry = parse_log_entry(line)
        if entry:
            event_id = entry['event_id']
            executions[event_id].update(entry)

    completed_executions = [ex for ex in executions.values() if 'result' in ex]

    total_techniques = len(completed_executions)
    successful_techniques = sum(1 for ex in completed_executions if ex['result'] == 'success')
    failed_techniques = sum(1 for ex in completed_executions if ex['result'] == 'failed')

    technique_counts = Counter(ex['technique'] for ex in completed_executions)
    tactic_counts = Counter(ex['tactic'] for ex in completed_executions)
    source_counts = Counter(ex['source'] for ex in completed_executions)

    start_time = min(datetime.fromisoformat(ex['timestamp']) for ex in executions.values())
    end_time = max(datetime.fromisoformat(ex['timestamp']) for ex in executions.values())
    duration = end_time - start_time

    # Per-source analysis
    per_source_analysis = defaultdict(lambda: {
        'total': 0,
        'successful': 0,
        'failed': 0,
        'techniques': defaultdict(list),
        'tactics': Counter(),
        'success_rate': 0,
        'unique_techniques': 0,
    })

    for ex in completed_executions:
        source = ex['source']
        per_source_analysis[source]['total'] += 1
        per_source_analysis[source]['techniques'][ex['technique']].append({
            'execution_time': ex['timestamp'],
            'result': ex['result'],
            'target': ex.get('target', 'N/A')
        })
        per_source_analysis[source]['tactics'][ex['tactic']] += 1
        
        if ex['result'] == 'success':
            per_source_analysis[source]['successful'] += 1
        else:
            per_source_analysis[source]['failed'] += 1

    for source, data in per_source_analysis.items():
        data['success_rate'] = (data['successful'] / data['total']) * 100 if data['total'] > 0 else 0
        data['unique_techniques'] = len(data['techniques'])

    return {
        'total_techniques': total_techniques,
        'successful_techniques': successful_techniques,
        'failed_techniques': failed_techniques,
        'technique_counts': technique_counts,
        'tactic_counts': tactic_counts,
        'source_counts': source_counts,
        'start_time': start_time,
        'end_time': end_time,
        'duration': duration,
        'per_source_analysis': per_source_analysis
    }

def generate_html_report(analysis):
    """Function to generate a HTML report from log analysis"""
    html_template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Halberd - Security Testing Summary</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }}
            h1, h2 {{
                color: #2c3e50;
            }}
            .section {{
                background-color: #f9f9f9;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 20px;
                margin-bottom: 20px;
            }}
            .metrics {{
                display: flex;
                justify-content: space-around;
                flex-wrap: wrap;
            }}
            .metric {{
                text-align: center;
                padding: 10px;
                background-color: #ecf0f1;
                border-radius: 5px;
                margin: 10px;
            }}
            .metric h3 {{
                margin: 0;
                color: #2980b9;
            }}
            .technique {{
                background-color: #e8f4f8;
                padding: 10px;
                margin-bottom: 10px;
                border-radius: 5px;
            }}
            .execution {{
                margin-left: 20px;
                font-size: 0.9em;
            }}
            .success {{
                color: #27ae60;
            }}
            .failure {{
                color: #c0392b;
            }}
            .chart-container {{
                width: 100%;
                max-width: 600px;
                margin: 20px auto;
            }}
        </style>
    </head>
    <body>
        <h1>Halberd Security Testing Summary Report</h1>
        
        <div class="section">
            <h2>1. Overview</h2>
            <p>Testing Period: {start_time} to {end_time}</p>
            <p>Total Duration: {duration}</p>
            <p>This report summarizes the results of a comprehensive security test. The testing emulated various attack techniques to identify potential gaps in controls and assess the detection & response capabilities.</p>
        </div>

        <div class="section">
            <h2>2. Key Metrics</h2>
            <div class="metrics">
                <div class="metric">
                    <h3>{total_techniques}</h3>
                    <p>Total techniques executed</p>
                </div>
                <div class="metric">
                    <h3>{successful_techniques} ({success_rate:.2f}%)</h3>
                    <p>Successful techniques</p>
                </div>
                <div class="metric">
                    <h3>{failed_techniques} ({failure_rate:.2f}%)</h3>
                    <p>Failed techniques</p>
                </div>
            </div>
            <div class="chart-container">
                <canvas id="techniquesChart"></canvas>
            </div>
        </div>

        <div class="section">
            <h2>3. Tactic Analysis</h2>
            <ul>
                {tactic_analysis}
            </ul>
            <div class="chart-container">
                <canvas id="tacticsChart"></canvas>
            </div>
        </div>

        <div class="section">
            <h2>4. Technique Analysis</h2>
            <ul>
                {technique_analysis}
            </ul>
        </div>

        <div class="section">
            <h2>5. Per-Source Detailed Analysis</h2>
            {per_source_analysis}
        </div>

        <script>
            // Techniques Chart
            var ctxTechniques = document.getElementById('techniquesChart').getContext('2d');
            var techniquesChart = new Chart(ctxTechniques, {{
                type: 'pie',
                data: {{
                    labels: ['Successful', 'Failed'],
                    datasets: [{{
                        data: [{successful_techniques}, {failed_techniques}],
                        backgroundColor: ['#27ae60', '#c0392b']
                    }}]
                }},
                options: {{
                    responsive: true,
                    title: {{
                        display: true,
                        text: 'Technique Execution Results'
                    }}
                }}
            }});

            // Tactics Chart
            var ctxTactics = document.getElementById('tacticsChart').getContext('2d');
            var tacticsChart = new Chart(ctxTactics, {{
                type: 'bar',
                data: {{
                    labels: {tactic_labels},
                    datasets: [{{
                        label: 'Number of Attempts',
                        data: {tactic_data},
                        backgroundColor: '#3498db'
                    }}]
                }},
                options: {{
                    responsive: true,
                    title: {{
                        display: true,
                        text: 'Tactics Usage'
                    }},
                    scales: {{
                        yAxes: [{{
                            ticks: {{
                                beginAtZero: true
                            }}
                        }}]
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    '''

    # Analyze tatics
    tactic_analysis = "\n".join(f"<li>{tactic}: {count} attempts</li>" for tactic, count in analysis['tactic_counts'].most_common())
    # Analyze techniques
    technique_analysis = "\n".join(f"<li>{technique}: {count} executions</li>" for technique, count in analysis['technique_counts'].most_common())

    # Analyze metrics per source / identity used for testing
    per_source_analysis = ""
    for source, data in analysis['per_source_analysis'].items():
        per_source_analysis += f'''
        <div class="source-section">
            <h3>Source: {source}</h3>
            <h4>Key Metrics:</h4>
            <ul>
                <li>Total techniques executed: {data['total']}</li>
                <li>Successful techniques: {data['successful']}</li>
                <li>Failed techniques: {data['failed']}</li>
                <li>Success rate: {data['success_rate']:.2f}%</li>
                <li>Unique techniques attempted: {data['unique_techniques']}</li>
            </ul>
            <h4>Techniques Used by Source:</h4>
        '''
        for technique, executions in data['techniques'].items():
            per_source_analysis += f'''
            <div class="technique">
                <h5>{technique}: {len(executions)} executions</h5>
            '''
            for execution in executions:
                result_class = 'success' if execution['result'] == 'success' else 'failure'
                per_source_analysis += f'''
                <div class="execution">
                    <p>Execution time: {execution['execution_time']}</p>
                    <p class="{result_class}">Execution result: {execution['result']}</p>
                    <p>Target: {execution['target']}</p>
                </div>
                '''
            per_source_analysis += "</div>"
        
        per_source_analysis += '''
            <h4>Tactics Focus:</h4>
            <ul>
        '''
        per_source_analysis += "\n".join(f"<li>{tactic}: {count} attempts</li>" for tactic, count in data['tactics'].most_common())
        per_source_analysis += '''
            </ul>
        </div>
        '''

    tactic_labels = json.dumps([tactic for tactic, _ in analysis['tactic_counts'].most_common()])
    tactic_data = json.dumps([count for _, count in analysis['tactic_counts'].most_common()])

    try:
        html_content = html_template.format(
            start_time=analysis['start_time'].strftime('%Y-%m-%d %H:%M'),
            end_time=analysis['end_time'].strftime('%Y-%m-%d %H:%M'),
            duration=analysis['duration'],
            total_techniques=analysis['total_techniques'],
            successful_techniques=analysis['successful_techniques'],
            failed_techniques=analysis['failed_techniques'],
            success_rate=(analysis['successful_techniques'] / analysis['total_techniques']) * 100,
            failure_rate=(analysis['failed_techniques'] / analysis['total_techniques']) * 100,
            tactic_analysis=tactic_analysis,
            technique_analysis=technique_analysis,
            per_source_analysis=per_source_analysis,
            tactic_labels=tactic_labels,
            tactic_data=tactic_data
        )
    except Exception as e:
        print(f"Error in generating HTML content: {str(e)}")
        print("Traceback:")
        print(traceback.format_exc())
        raise

    return html_content