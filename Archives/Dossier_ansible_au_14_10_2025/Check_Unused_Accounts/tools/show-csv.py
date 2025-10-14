import csv

def display_csv_basic(file_path):
	"""
	Displays the content of a CSV file line by line
	"""
	try:
		with open(file_path,'r', newline='') as csvfile:
			reader = csv.reader(csvfile)
			for row in reader:
				print(', '.join(row))
	except FileNotFoundError:
		print(f"Error: File not found at '{file_path}'")
	except Exception as e:
		print(f"An error occured: {e}")


display_csv_basic('test.csv')

