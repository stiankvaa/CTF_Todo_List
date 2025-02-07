# Start from a lightweight base image
FROM python:3.12
USER nonroot


# Set the working directory in the container
WORKDIR /app/

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy the Flask app into the container
COPY . /app/

# Expose the port that Flask will run on
EXPOSE 5000

# Command to run your Flask app
CMD ["python", "run.py"]
