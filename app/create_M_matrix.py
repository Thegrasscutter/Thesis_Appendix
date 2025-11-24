#!/usr/bin/env python3
"""
Script to parse and update the MITRE-to-NICE vulnerability analysis CSV file.
This script allows updating weights for specific IDs in the CSV file.
"""

import csv
import os
import sys
from typing import Dict, List, Optional


def read_csv(file_path: str) -> tuple[List[str], List[List[str]]]:
    """
    Read the CSV file and return the header and data.
    
    Args:
        file_path: Path to the CSV file
        
    Returns:
        Tuple containing header list and data rows list
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            header = next(csv_reader)
            data = [row for row in csv_reader]
        return header, data
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        sys.exit(1)


def find_row_by_id(data: List[List[str]], target_id: str) -> Optional[int]:
    """
    Find a row in the CSV data by its ID.
    
    Args:
        data: List of data rows
        target_id: ID to search for
        
    Returns:
        Index of the row if found, None otherwise
    """
    for i, row in enumerate(data):
        if len(row) > 1 and row[1] == target_id:
            return i
    return None


def update_row_weights(data: List[List[str]], row_index: int, header: List[str], weight: str) -> None:
    """
    Update a row's weights with the specified value.
    
    Args:
        data: List of data rows
        row_index: Index of the row to update
        header: Header row containing column names
        weight: Weight value to set
    """
    # Skip the first 3 columns (Category, ID, Statement)
    for i in range(3, len(data[row_index])):
        data[row_index][i] = weight
    return data[row_index]


def update_weights(file_path: str, target_id: str, weight: float) -> None:
    """
    Update weights for a specific ID in the CSV file.
    
    Args:
        file_path: Path to the CSV file
        target_id: ID to update weights for
        weight: Weight value to set
    """
    # Read the CSV file
    header, data = read_csv(file_path)
    
    # Find the row with the specified ID
    row_index = find_row_by_id(data, target_id)
    
    if row_index is not None:
        # Get the statement from the row for confirmation
        statement = data[row_index][2] if len(data[row_index]) > 2 else "N/A"
        #print(f"Found ID {target_id}: {statement}")
        output = data[row_index][:3]
        # Update the weights
        for col in range(3, len(header)):
            if data[row_index][col] != '':
                output.append(float(data[row_index][col]) * weight)
            else:
                output.append(0)
        return output
    else:
        print(f"ID {target_id} not found in the CSV file.")

def sum_columns(data: List[List[str]], col_start: int, col_end: int) -> List[float]:
    """
    Sum the values in the specified columns for each row in the data.
    
    Args:
        data: List of data rows
        col_start: Starting column index (inclusive)
        col_end: Ending column index (exclusive)
        
    Returns:
        List of summed values for each row
    """
    sums = []
    
    for row in data:
        total = sum(float(row[i]) for i in range(col_start, col_end) if row[i].isdigit())
        sums.append(total)
    return sums

def get_nice_weights(file_name):
    nice_weights = {}
    nice_id = {}
    with open(file_name, 'r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        header = next(csv_reader)
        for row in csv_reader:
            if len(row) > 1:
                nice_id[row[1]] = row[1]
                nice_weights[row[1]] = float(row[-1])/97  # Assuming the last column is the weight
        nice_touple = zip(nice_id.values(), nice_weights.values())
    return nice_touple

def main():
    """Main function to run the script."""
    nice_touple = get_nice_weights("../baseline_files/NICE_Weighting.csv")

    # Define the path to the CSV file
    csv_file_path = "../baseline_files/MITRE-to-NICE-raw.csv"
    temp = []
    output = []
    with open(csv_file_path, 'r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        header = next(csv_reader)
        output.append(header)  # Add header as the first row in output
        file.close()

    # Update the weights for the specified ID
    for row in nice_touple:
        temp.append(update_weights(csv_file_path, row[0], row[1]))

    # Sort temp by the first column if needed
    temp.sort(key=lambda x: x[0] if len(x) > 0 else "")

    # Add all rows from temp to output
    for row in temp:
        if row:  # Only add non-empty rows
            output.append(row)
            
    # At this point, output contains the CSV structure with header and data rows
    # You can access this data without writing to a file
    print(f"CSV structure created with {len(output)-1} data rows")
    # Calculate the sum for each column starting from index 3
    column_sums = [0] * (len(output[0]) - 3)
    for row in output[1:]:  # Skip header
        for i in range(3, len(row)):
            # Convert to integer if possible, otherwise add 0
            try:
                column_sums[i-3] += row[i]
            except (ValueError, IndexError):
                # Skip if value is not an integer or index is out of range
                pass
    # Create a new CSV file for column sums
    with open("../baseline_files/MITRE-to-NICE-M-matrix.csv", 'w', newline='', encoding='utf-8') as sum_file:
        sum_writer = csv.writer(sum_file)
        sum_writer.writerow(["MITRE_TTP", "Sum"])  # Write header
        
        for i, col_sum in enumerate(column_sums):
            col_name = output[0][i+3]
            sum_writer.writerow([col_name, col_sum])

    print("Column sums written to ../baseline_files/MITRE-to-NICE-M-matrix.csv")


if __name__ == "__main__":
    main()
