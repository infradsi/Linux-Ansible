import pandas as pd

def display_csv_pandas(file_path):
    """
    Displays the content of a CSV file using pandas DataFrame.
    """
    try:
        df = pd.read_csv(file_path)
        print(df) # Prints the entire DataFrame
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
    except pd.errors.EmptyDataError:
        print(f"Error: The CSV file '{file_path}' is empty.")
    except Exception as e:
        print(f"An error occurred: {e}")


def hello():
    """
    Display script infos
    """
    print("This script display CSV file",'\n')



# Example usage:
# Assuming 'test.csv' is in the same directory as your Python script

hello()
display_csv_pandas('test.csv')