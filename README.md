# RevKeen Python SDK

Official Python SDK for the RevKeen API - Stripe-like billing infrastructure for your SaaS.

## Installation

```bash
pip install revkeen
```

## Usage

```python
from revkeen import RevKeen

client = RevKeen(api_key="rk_live_...")

# List customers
customers = client.customers.list()
```

## Documentation

- [API Reference](https://api.revkeen.com/v2/docs)
- [RevKeen Website](https://revkeen.com)
