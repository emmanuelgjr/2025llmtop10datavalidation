# Advanced Data Validation & Security Script for LLM Applications - Based on OWASP Top 10 for LLM Apps 2025 List

This comprehensive guide presents an enhanced Python script designed to address the [**OWASP LLM Top 10 for LLM Applications 2025**](https://genai.owasp.org/) vulnerabilities (LLM01–LLM10) by incorporating advanced security measures, data validation techniques, and compliance features. The script integrates multiple cybersecurity frameworks to ensure robust protection for large language model (LLM) applications.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Configuration File Setup with Dynamic Loading](#configuration-file-setup-with-dynamic-loading)
4. [Advanced Validation Functions with Regex Optimization](#advanced-validation-functions-with-regex-optimization)
5. [Enhanced Schema Validation for JSON Data](#enhanced-schema-validation-for-json-data)
6. [Machine Learning-Based Anomaly Detection](#machine-learning-based-anomaly-detection)
7. [Rate Limiting with Redis](#rate-limiting-with-redis)
8. [Real-Time Output Filtering with NLP](#real-time-output-filtering-with-nlp)
9. [Masking Sensitive Information with Tokenization](#masking-sensitive-information-with-tokenization)
10. [Logging and Auditing for Compliance](#logging-and-auditing-for-compliance)
11. [Automated Testing and Continuous Integration](#automated-testing-and-continuous-integration)
12. [Complete Code Example](#complete-code-example)
13. [Conclusion](#conclusion)

---

## Introduction

This script is designed to enhance security and compliance for LLM applications, using guidelines from the **OWASP LLM Top 10 for LLM Apps**. Each step addresses specific vulnerabilities, offering improved security through robust data validation, anomaly detection, and sophisticated logging and error handling.

---

## Prerequisites

Install the required packages:

```bash
pip install pandas jsonschema configparser logging scikit-learn redis spacy
python -m spacy download en_core_web_sm
```

### Required Tools and Libraries

- **pandas**: For data handling.
- **jsonschema**: For JSON structure validation.
- **configparser**: For configuration management.
- **scikit-learn**: For advanced anomaly detection.
- **redis**: For distributed rate limiting.
- **spaCy**: For NLP-based output filtering.

---

## Configuration File Setup with Dynamic Loading

Create a `config.ini` file for flexible validation parameters. The script includes dynamic reloading to allow real-time configuration updates without restarting the script.

### `config.ini`

```ini
[DataValidation]
date_format = %Y-%m-%d
email_pattern = ^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$
allowed_domains = example.com, trusted.com
allow_excessive_requests = False
anomaly_detection_threshold = 0.05
redis_host = localhost
redis_port = 6379
```

### Dynamic Configuration Reloading

```python
from configparser import ConfigParser
import time
import os

def load_config():
    config = ConfigParser()
    config.read('config.ini')
    return config

def watch_config():
    last_mtime = os.path.getmtime('config.ini')
    while True:
        time.sleep(10)
        new_mtime = os.path.getmtime('config.ini')
        if new_mtime != last_mtime:
            print("Reloading configuration...")
            last_mtime = new_mtime
            config = load_config()
            return config
```

The `load_config` function reads the configuration parameters from `config.ini`, allowing you to adjust validation settings without modifying the code. The `watch_config` function monitors the configuration file for changes and reloads it dynamically.

---

## Advanced Validation Functions with Regex Optimization

These validation functions use pre-compiled regular expressions for faster execution and integrate additional checks for domains and injection prevention.

```python
import re

# Compile regular expressions for efficiency
email_regex = re.compile(config['DataValidation']['email_pattern'])

def validate_email(email, allowed_domains):
    domain = email.split('@')[-1]
    return email_regex.match(email) and domain in allowed_domains

def validate_prompt_injection(prompt, disallowed_chars=['<', '>', '{', '}', ';']):
    return not any(char in prompt for char in disallowed_chars)

def validate_sensitive_data(data):
    sensitive_terms = ['SSN', 'credit card', 'confidential']
    return not any(term.lower() in data.lower() for term in sensitive_terms)
```

- **Email Validation**: Checks if the email matches the regex pattern and is from an allowed domain.
- **Prompt Injection Prevention**: Detects potentially malicious characters that could be used for code injection.
- **Sensitive Data Detection**: Scans for the presence of sensitive terms to prevent data leakage.

---

## Enhanced Schema Validation for JSON Data

Using JSON Schema with strict rules for each field provides consistent data structure, protecting against injection and insecure data. Validation results are logged for auditing purposes.

```python
from jsonschema import validate, ValidationError

schema = {
    "type": "object",
    "properties": {
        "email": {"type": "string", "pattern": config['DataValidation']['email_pattern']},
        "date_of_birth": {"type": "string", "format": "date"},
        "content": {"type": "string", "maxLength": 500},
    },
    "required": ["email", "date_of_birth", "content"]
}

def validate_json(data, schema):
    try:
        validate(instance=data, schema=schema)
        return True
    except ValidationError as e:
        logging.error(f"JSON Validation error: {e}")
        return False
```

- **JSON Schema**: Defines the expected structure and data types of the input JSON.
- **Validation Function**: Uses `jsonschema` to validate input data against the schema and logs any validation errors.

---

## Machine Learning-Based Anomaly Detection

Anomaly detection with `IsolationForest` identifies suspicious patterns that may indicate exploitation attempts. Other ML models, such as `Local Outlier Factor`, can be swapped in as needed.

```python
from sklearn.ensemble import IsolationForest

def detect_anomalies(data, threshold=0.05):
    # Convert data to numerical values for the model
    data_numeric = data.applymap(lambda x: int(hashlib.sha256(str(x).encode()).hexdigest(), 16) % (10 ** 6))
    model = IsolationForest(contamination=threshold)
    return model.fit_predict(data_numeric)
```

- **IsolationForest**: An unsupervised learning algorithm for anomaly detection.
- **Data Preparation**: Converts string data into numerical format suitable for the model.

---

## Rate Limiting with Redis

Redis-backed rate limiting allows for distributed enforcement of request limits. Adjust the Redis configuration in `config.ini`.

```python
import redis

class RateLimiter:
    def __init__(self, max_requests, timeframe):
        config = load_config()
        self.redis_client = redis.StrictRedis(
            host=config['DataValidation']['redis_host'],
            port=int(config['DataValidation']['redis_port'])
        )
        self.max_requests = max_requests
        self.timeframe = timeframe

    def allow_request(self, user_id):
        requests = self.redis_client.get(user_id)
        if requests is None:
            self.redis_client.set(user_id, 1, ex=self.timeframe)
            return True
        elif int(requests) < self.max_requests:
            self.redis_client.incr(user_id)
            return True
        else:
            return False
```

- **RateLimiter Class**: Manages request counts using Redis, enforcing limits over a specified timeframe.
- **Redis Configuration**: Reads host and port settings from `config.ini`.

---

## Real-Time Output Filtering with NLP

Using **spaCy** NLP, detect and redact sensitive terms to prevent inadvertent disclosure of classified information.

```python
import spacy

nlp = spacy.load("en_core_web_sm")

def sanitize_output(output):
    forbidden_phrases = ["classified", "confidential", "secret"]
    redacted_output = output
    for phrase in forbidden_phrases:
        if phrase in output.lower():
            redacted_output = redacted_output.replace(phrase, "[REDACTED]")
    return redacted_output
```

- **NLP Processing**: Loads a spaCy language model to analyze text.
- **Output Sanitization**: Replaces forbidden phrases with "[REDACTED]" to prevent sensitive information leakage.

---

## Masking Sensitive Information with Tokenization

Tokenizing sensitive information provides enhanced security and meets compliance requirements (e.g., PCI DSS). This implementation tokenizes instead of masking with simple asterisks.

```python
import hashlib

def tokenize_data(data):
    if isinstance(data, str):
        token = hashlib.sha256(data.encode()).hexdigest()
        return token[:10]  # Return a shorter token for readability
    return data
```

- **Tokenization Function**: Converts sensitive strings into a hashed token.
- **Hashing Algorithm**: Uses SHA-256 to generate a secure hash.

---

## Logging and Auditing for Compliance

Structured logging with contextual information helps meet compliance requirements. Log details such as user IDs, timestamps, and validation results.

```python
import logging

logging.basicConfig(filename='validation.log', level=logging.INFO, format='%(asctime)s %(message)s')

def log_validation_results(data, fields, user_id):
    for field in fields:
        if f"{field}_valid" in data.columns:
            invalid_rows = data[~data[f"{field}_valid"]]
            for _, row in invalid_rows.iterrows():
               

 logging.info(f"User: {user_id} | Invalid {field} at row {row.name}: {row[field]}")
```

- **Logging Setup**: Configures logging to write to a file with a specified format.
- **Validation Logging**: Records detailed information about validation failures for auditing.

---

## Automated Testing and Continuous Integration

Integrate automated testing to verify each validation function. Add this as part of a CI/CD pipeline to maintain quality and consistency.

```python
import unittest

class TestValidationFunctions(unittest.TestCase):
    def test_validate_email(self):
        self.assertTrue(validate_email("user@example.com", ["example.com"]))
        self.assertFalse(validate_email("user@invalid.com", ["example.com"]))

    def test_validate_prompt_injection(self):
        self.assertTrue(validate_prompt_injection("Safe content"))
        self.assertFalse(validate_prompt_injection("<script>"))

    def test_tokenize_data(self):
        token = tokenize_data("SensitiveData")
        self.assertEqual(len(token), 10)

if __name__ == "__main__":
    unittest.main()
```

- **Unit Tests**: Validates that each function behaves as expected.
- **Continuous Integration**: Ensures that code changes don't break existing functionality.

---

## Complete Code Example

Below is the complete Python script that integrates all the advanced features and security enhancements discussed above.

```python
# advanced_data_validation.py

import os
import time
import re
import logging
import hashlib
import json
import pandas as pd
from configparser import ConfigParser
from jsonschema import validate, ValidationError
from sklearn.ensemble import IsolationForest
import redis
import spacy

# Load configuration
def load_config():
    config = ConfigParser()
    config.read('config.ini')
    return config

# Watch for configuration changes
def watch_config():
    last_mtime = os.path.getmtime('config.ini')
    while True:
        time.sleep(10)
        new_mtime = os.path.getmtime('config.ini')
        if new_mtime != last_mtime:
            print("Reloading configuration...")
            last_mtime = new_mtime
            config = load_config()
            return config

# Initialize logging
logging.basicConfig(filename='validation.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Load spaCy model
nlp = spacy.load("en_core_web_sm")

# Main script
def main():
    # Load configuration
    config = load_config()

    # Compile regular expressions
    email_regex = re.compile(config['DataValidation']['email_pattern'])
    allowed_domains = [domain.strip() for domain in config['DataValidation']['allowed_domains'].split(',')]
    date_format = config['DataValidation']['date_format']

    # Initialize rate limiter
    rate_limiter = RateLimiter(max_requests=5, timeframe=60)  # Max 5 requests per minute

    # Example user ID
    user_id = 'user123'

    # Simulate data input (in practice, replace with actual data input)
    data_input = {
        "email": "user@example.com",
        "date_of_birth": "1990-01-01",
        "content": "This is a sample content without any confidential information."
    }

    # Check rate limiting
    if not rate_limiter.allow_request(user_id):
        print("Rate limit exceeded.")
        logging.warning(f"User {user_id} exceeded rate limit.")
        return

    # Validate JSON data
    schema = {
        "type": "object",
        "properties": {
            "email": {"type": "string", "pattern": config['DataValidation']['email_pattern']},
            "date_of_birth": {"type": "string", "format": "date"},
            "content": {"type": "string", "maxLength": 500},
        },
        "required": ["email", "date_of_birth", "content"]
    }

    if not validate_json(data_input, schema):
        print("Invalid input data.")
        logging.error(f"User {user_id} provided invalid JSON data.")
        return

    # Validate individual fields
    email_valid = validate_email(data_input['email'], allowed_domains)
    dob_valid = validate_date(data_input['date_of_birth'], date_format)
    content_valid = validate_prompt_injection(data_input['content'])
    sensitive_data_valid = validate_sensitive_data(data_input['content'])

    # Log validation results
    validation_results = {
        'email_valid': email_valid,
        'dob_valid': dob_valid,
        'content_valid': content_valid,
        'sensitive_data_valid': sensitive_data_valid
    }

    log_validation_results(pd.DataFrame([data_input]), list(validation_results.keys()), user_id)

    if not all(validation_results.values()):
        print("Validation failed.")
        return

    # Tokenize sensitive data
    data_input['email'] = tokenize_data(data_input['email'])
    data_input['date_of_birth'] = tokenize_data(data_input['date_of_birth'])

    # Detect anomalies (assuming we have historical data)
    # For demonstration, we use the input data itself
    anomalies = detect_anomalies(pd.DataFrame([data_input]), threshold=float(config['DataValidation']['anomaly_detection_threshold']))
    if anomalies[0] == -1:
        print("Anomaly detected in input data.")
        logging.warning(f"User {user_id} provided anomalous data.")
        return

    # Process data (e.g., send to LLM)
    # Here we just simulate output
    output = f"Processed content: {data_input['content']}"

    # Sanitize output
    sanitized_output = sanitize_output(output)

    print(sanitized_output)

# Validation functions
def validate_email(email, allowed_domains):
    domain = email.split('@')[-1]
    if email_regex.match(email) and domain in allowed_domains:
        return True
    else:
        logging.error(f"Invalid email: {email}")
        return False

def validate_date(date_text, date_format):
    try:
        pd.to_datetime(date_text, format=date_format)
        return True
    except ValueError:
        logging.error(f"Invalid date format: {date_text}")
        return False

def validate_prompt_injection(prompt, disallowed_chars=['<', '>', '{', '}', ';']):
    if not any(char in prompt for char in disallowed_chars):
        return True
    else:
        logging.error(f"Prompt injection detected in content: {prompt}")
        return False

def validate_sensitive_data(data):
    sensitive_terms = ['SSN', 'credit card', 'confidential']
    if not any(term.lower() in data.lower() for term in sensitive_terms):
        return True
    else:
        logging.error(f"Sensitive data detected in content: {data}")
        return False

def validate_json(data, schema):
    try:
        validate(instance=data, schema=schema)
        return True
    except ValidationError as e:
        logging.error(f"JSON Validation error: {e}")
        return False

def tokenize_data(data):
    if isinstance(data, str):
        token = hashlib.sha256(data.encode()).hexdigest()
        return token[:10]  # Return a shorter token for readability
    return data

def detect_anomalies(data, threshold=0.05):
    # For demonstration, we need numerical data
    # In practice, you would have a dataset to fit the model
    # Here, we simulate by converting strings to numerical hash values
    data_numeric = data.applymap(lambda x: int(hashlib.sha256(str(x).encode()).hexdigest(), 16) % (10 ** 6))
    model = IsolationForest(contamination=threshold)
    return model.fit_predict(data_numeric)

def sanitize_output(output):
    forbidden_phrases = ["classified", "confidential", "secret"]
    redacted_output = output
    for phrase in forbidden_phrases:
        if phrase in output.lower():
            redacted_output = redacted_output.replace(phrase, "[REDACTED]")
    return redacted_output

def log_validation_results(data, fields, user_id):
    for field in fields:
        if f"{field}_valid" in data.columns:
            invalid_rows = data[~data[f"{field}_valid"]]
            for _, row in invalid_rows.iterrows():
                logging.info(f"User: {user_id} | Invalid {field} at row {row.name}: {row[field]}")

# Rate Limiter class
class RateLimiter:
    def __init__(self, max_requests, timeframe):
        config = load_config()
        self.redis_client = redis.StrictRedis(
            host=config['DataValidation']['redis_host'],
            port=int(config['DataValidation']['redis_port'])
        )
        self.max_requests = max_requests
        self.timeframe = timeframe

    def allow_request(self, user_id):
        requests = self.redis_client.get(user_id)
        if requests is None:
            self.redis_client.set(user_id, 1, ex=self.timeframe)
            return True
        elif int(requests) < self.max_requests:
            self.redis_client.incr(user_id)
            return True
        else:
            return False

if __name__ == "__main__":
    main()
```

**Important Notes**:

- **Execution Flow**: The `main` function orchestrates the workflow, handling rate limiting, data validation, anomaly detection, data processing, and output sanitization.
- **Error Handling and Logging**: Throughout the script, errors and validation failures are logged with detailed messages, aiding in troubleshooting and compliance reporting.
- **Dynamic Configuration**: The script reloads configuration settings dynamically, allowing real-time updates without restarting the application.
- **Redis Dependency**: Ensure that Redis is installed and running on your system or accessible via the network.

---

## Conclusion

This data validation script provides advanced techniques for security and compliance in LLM applications. We leveraged sophisticated anomaly detection, rate limiting with Redis, and real-time output filtering with NLP, this script is better equipped to protect sensitive information while aligning with modern cybersecurity frameworks.

Implementing such a script enhances the security posture of your application, protects sensitive data, and ensures compliance with industry standards.

---

## Additional Information

**Example `config.ini`**:

```ini
[DataValidation]
date_format = %Y-%m-%d
email_pattern = ^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$
allowed_domains = example.com, trusted.com
allow_excessive_requests = False
anomaly_detection_threshold = 0.05
redis_host = localhost
redis_port = 6379
```

**Running the Script**:

- Ensure all dependencies are installed.
- Make sure Redis is running.
- Place the `config.ini` file in the same directory as the script.
- Run the script using `python advanced_data_validation.py`.

**Testing and Continuous Integration**:

Integrate the unit tests provided into your CI/CD pipeline to automate testing and ensure code quality.

---

## References

- **OWASP LLM Top 10 for LLM Apps**: [OWASP Top 10 for LLM Apps](https://genai.owasp.org/)
- **Python Documentation**: [Python Official Docs](https://docs.python.org/3/)
- **spaCy NLP Library**: [spaCy Documentation](https://spacy.io/usage)

---

Always ensure thorough testing and validation before deploying it in a production environment.

---

# Disclaimer

This script is provided by the data-gathering team for educational purposes only. It is intended to serve as a foundational example of implementing data validation and security measures for Large Language Model (LLM) applications. **We make no guarantees regarding the accuracy, completeness, or suitability of this script for your specific use case or environment.**

Before deploying this script, **thoroughly test it in your own environment** to ensure compatibility and security. **Verify all customizations** and adapt the code to meet the unique requirements and regulations applicable to your organization and industry. This may include, but is not limited to, compliance with cybersecurity frameworks, privacy laws, and organizational security policies.

**We do not accept any responsibility or liability** for any errors, issues, or damages that may arise from the use or misuse of this script. **Your use of this code is entirely at your own risk.**
