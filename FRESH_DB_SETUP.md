# Fresh Database Setup - Contributors Badge System

## Quick Commands for VM

```bash
# 1. Pull latest code
cd ~/pgweb
git pull origin badges3

# 2. Drop and recreate database
dropdb pgweb
createdb pgweb

# 3. Setup Varnish functions + run migrations + load demo data
./setup_vm_database.sh

# 4. Start server
python manage.py runserver 0.0.0.0:8000
```

Done! Go to: http://your-vm-ip:8000/community/people/

---

## Detailed Steps (if needed)

### Step 1: Pull Latest Code
```bash
cd ~/pgweb
git pull origin badges3  # or your remote
```

### Step 2: Drop Database (PostgreSQL)
```bash
# Make sure no connections to database
dropdb pgweb

# If you get "database is being accessed by other users":
# Kill the Django dev server first (Ctrl+C)
# Then try again
```

### Step 3: Create Fresh Database
```bash
createdb pgweb
```

### Step 4: Create Varnish Functions (for local dev)
```bash
psql pgweb < sql/varnish_local.sql
```

This creates dummy `varnish_purge()` functions needed by pgweb but not used in development.

### Step 5: Run Migrations
```bash
source venv/bin/activate  # if not already activated
python manage.py migrate
```

Expected output should include:
```
Applying contenttypes.0001_initial... OK
Applying auth.0001_initial... OK
...
Applying contributors.0004_alter_contributor_contribution_and_more... OK
```

### Step 6: Load Fixtures (optional, setup script does this)
```bash
python manage.py loaddata pgweb/core/fixtures/data.json
python manage.py loaddata pgweb/contributors/fixtures/data.json
```

This creates:
- Organization types (Open Source Project, Not for profit, etc.)
- Contributor types (Core Team, Major Contributors, etc.)

### Step 7: Load Demo Data
```bash
python manage.py shell < setup_badge_demo_data.py
```

This creates:
- 7 test users
- 3 demo organizations
- 5 badges
- Sample contributor profiles

### Step 8: Start Server
```bash
python manage.py runserver 0.0.0.0:8000
```

---

## Or Use the Automated Script

The `setup_vm_database.sh` script does steps 4-7 automatically:

```bash
./setup_vm_database.sh
```

---

## Verify Setup

### Quick Check
```bash
python manage.py shell
```

```python
from pgweb.contributors.models import Badge, Contributor
from pgweb.core.models import OrganisationType
from django.contrib.auth.models import User

# Check types loaded
print(f"Org types: {OrganisationType.objects.count()}")  # Should be 5+

# Check demo data
print(f"Users: {User.objects.count()}")  # Should be 7+
print(f"Badges: {Badge.objects.count()}")  # Should be 5
print(f"Approved badges: {Badge.objects.filter(approved=True).count()}")  # Should be 4

# Check specific user
alice = User.objects.get(username='alice')
print(f"Alice exists: {alice.email}")
```

### Test URLs
- http://your-vm-ip:8000/community/people/
- http://your-vm-ip:8000/community/people/alice/
- http://your-vm-ip:8000/admin/pending/ (login: moderator / moderator123)

---

## Login Credentials

See **DEMO_CREDENTIALS.md** for the full list, but here are the essentials:

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Superuser |
| moderator | moderator123 | Can approve badges |
| orgmanager1 | manager123 | Manages organizations |
| alice | alice123 | Badge holder with profile |

---

## Troubleshooting

### "dropdb: error: database 'pgweb' is being accessed by other users"

**Solution:** Kill the Django dev server first
```bash
# Press Ctrl+C in the terminal where runserver is running
# Then try dropdb again
```

### "createdb: error: database 'pgweb' already exists"

**Solution:** You need to drop it first
```bash
dropdb pgweb
createdb pgweb
```

### "password authentication failed for user"

**Solution:** Check your `settings_local.py` database credentials
```python
# In pgweb/settings_local.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'pgweb',
        'USER': 'your_db_user',
        'PASSWORD': 'your_db_password',
        'HOST': 'localhost',
    }
}
```

### "relation X does not exist"

**Solution:** Migrations not run
```bash
python manage.py migrate
```

---

## Alternative: SQLite for Quick Testing

If you don't want to deal with PostgreSQL:

```python
# In pgweb/settings_local.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}
```

Then:
```bash
rm db.sqlite3  # if it exists
python manage.py migrate
./setup_vm_database.sh
```

---

**Last Updated:** 2026-01-20
