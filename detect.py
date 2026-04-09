import pandas as pd
import joblib
import sys

# Ensure Pandas doesn't cut off long URLs with "..." in the terminal
pd.set_option('display.max_colwidth', None)

def generate_human_report(anomaly_row, normal_medians):
    method = anomaly_row['Method']
    url = str(anomaly_row['URL'])
    
    # Truncate the URL slightly just in case it's thousands of characters long, 
    # but keep enough to clearly identify the attack payload.
    short_url = url[:150] + "..." if len(url) > 150 else url
    
    url_len = anomaly_row['url_length']
    payload_size = anomaly_row['lenght']
    
    # Start the report
    report = f"\n⚠️  CRITICAL ANOMALY: {method} request to [{short_url}]"
    
    # Logic 1: Check for URL Bloat (SQLi, XSS)
    if url_len > (normal_medians['url_length'] * 3):
        multiplier = int(url_len / normal_medians['url_length'])
        report += f"\n   -> Context: The URL is {url_len} characters long, which is {multiplier}x larger than the baseline average of {int(normal_medians['url_length'])}. This structural deviation is highly indicative of SQL Injection or Cross-Site Scripting (XSS)."
        
    # Logic 2: Check for Payload Bloat (Buffer Overflow, Data Exfil)
    # We add a buffer of 100 bytes so we don't flag tiny differences
    if payload_size > (normal_medians['lenght'] * 3) + 100:
        report += f"\n   -> Context: The request payload is {payload_size} bytes. Normal traffic on this network averages {int(normal_medians['lenght'])} bytes. This massive spike suggests a Buffer Overflow attempt or an unauthorized file upload."

    # Logic 3: The "Low and Slow" fallback
    if "Context:" not in report:
        report += f"\n   -> Context: The combination of the request method, payload, and endpoint sequencing deviates from historical baseline traffic. Review for Business Logic Abuse or sequential scanning."

    return report

def analyze_logs(csv_filepath):
    print(f"--- API-Sentinel Log Analyzer ---")
    print(f"Loading AI Model...")
    
    try:
        # Load the saved model and encoder
        model = joblib.load('api_sentinel_model.pkl')
        le = joblib.load('method_encoder.pkl')
    except FileNotFoundError:
        print("Error: Could not find the model files. Did you run the Jupyter Notebook first?")
        return

    print(f"Analyzing {csv_filepath}...")
    
    # Load new data
    try:
        df = pd.read_csv(csv_filepath)
    except FileNotFoundError:
        print(f"Error: Could not find the file {csv_filepath}")
        return

    # Prepare features
    df['url_length'] = df['URL'].astype(str).apply(len)
    df['Method'] = df['Method'].fillna('UNKNOWN')
    
    # Handle unknown HTTP methods safely
    known_classes = list(le.classes_)
    df['Method'] = df['Method'].apply(lambda x: x if x in known_classes else known_classes[0])
    df['method_encoded'] = le.transform(df['Method'])
    
    df['lenght'] = pd.to_numeric(df['lenght'], errors='coerce').fillna(0)

    # Make predictions
    features = ['url_length', 'method_encoded', 'lenght']
    df['anomaly_score'] = model.predict(df[features])

    # Extract anomalies
    anomalies = df[df['anomaly_score'] == -1]
    
    print("\n[+] Scan Complete.")
    print(f"Total Requests Scanned: {len(df)}")
    print(f"Threats Detected: {len(anomalies)}")
    
    if len(anomalies) > 0:
        print("\n" + "="*70)
        print("                 GENERATING HUMAN-READABLE THREAT REPORTS")
        print("="*70)
        
        # Calculate the baseline of what "Normal" looks like to compare against
        normal_traffic = df[df['anomaly_score'] == 1]
        normal_medians = {
            'url_length': normal_traffic['url_length'].median(),
            'lenght': normal_traffic['lenght'].median()
        }
        
        # To avoid spamming the console, let's just print the top 5 worst threats
        top_threats = anomalies.head(5)
        
        for index, row in top_threats.iterrows():
            # Generate and print the contextual report for each threat
            print(generate_human_report(row, normal_medians))
            print("-" * 70)
            
        print(f"\nLog saved. {len(anomalies) - len(top_threats)} additional anomalies suppressed from terminal view.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detect.py <path_to_log_csv>")
    else:
        target_file = sys.argv[1]
        analyze_logs(target_file)