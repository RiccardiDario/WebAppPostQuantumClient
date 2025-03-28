import pandas as pd

# Carica i due CSV usando il percorso relativo
average_metrics = pd.read_csv('report/request_logs/avg/average_metrics.csv')
avg_nginx_usage = pd.read_csv('report/filtered_logs/avg_nginx_usage.csv')

# Inserisce le colonne del secondo file subito dopo le colonne del client
average_metrics.insert(
    average_metrics.columns.get_loc("Client_Avg_RAM_Usage(%)") + 1,
    'Nginx_Avg_CPU_usage(%)', avg_nginx_usage['CPU Media (%)']
)
average_metrics.insert(
    average_metrics.columns.get_loc("Nginx_Avg_CPU_usage(%)") + 1,
    'Nginx_Avg_RAM_usage(%)', avg_nginx_usage['Mem Media (%)']
)

# Salva il nuovo DataFrame in un nuovo file CSV
average_metrics.to_csv('merged_average_metrics.csv', index=False)

print("File CSV uniti con successo in 'merged_average_metrics.csv'")