# Start with a lightweight base image
FROM python:3.12-slim

RUN pip3 install -v awscli==1.29.50
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
    
# Set the working directory inside the container
WORKDIR /app

# Copy only the requirements file and install dependencies
COPY ./SSO/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --upgrade python-jose

# Copy the rest of the application code
COPY ./SSO .

# Set the default command to run the Python script
#CMD ["python", "your_script.py"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
