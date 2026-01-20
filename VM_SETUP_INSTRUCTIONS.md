# VM Setup Instructions - Contributors Badge System

## Quick Setup (3 commands)

```bash
# 1. Make the setup script executable
chmod +x setup_vm_database.sh

# 2. Run the setup (migrations + demo data)
./setup_vm_database.sh

# 3. Start the server
python manage.py runserver 0.0.0.0:8000
```

That's it! Go to `http://your-vm-ip:8000/community/people/` to see the results.

---

## Manual Setup (if script doesn't work)

### Step 1: Run Migrations

```bash
cd ~/pgweb
source venv/bin/activate  # or however you activate your venv
python manage.py migrate
```

**Expected output:**
```
Running migrations:
  Applying contributors.0004_alter_contributor_contribution_and_more... OK
```

This creates:
- `contributors_badge` table
- `contributors_badge_holders` table (ManyToMany)
- Updates `contributors_contributor` table (makes `ctype` nullable)

### Step 2: Load Demo Data

```bash
python manage.py shell < setup_badge_demo_data.py
```

**Expected output:**
```
======================================================================
SETTING UP BADGE DEMO DATA
======================================================================

1. Cleaning up existing data...
  ✓ Cleaned up existing badges
  ✓ Cleaned up existing test users/orgs

2. Creating organization types...
  ✓ Created 'Community' org type

[... lots more output ...]

DEMO DATA SETUP COMPLETE!
```

### Step 3: Start Server

```bash
python manage.py runserver 0.0.0.0:8000
```

---

## Verify Setup

### Quick Test URLs

Visit these URLs (not logged in):

1. **http://your-vm-ip:8000/community/people/**
   - Should show: Badge holders list and badges list
   - Should see: alice, bob (have profiles)
   - Should NOT see: charlie (no profile yet)

2. **http://your-vm-ip:8000/community/people/alice/**
   - Should show: Alice's profile with 3 badges

3. **http://your-vm-ip:8000/community/badge/1/**
   - Should show: "PGConf.dev 2025 Speaker" badge
   - Should show: Badge holders (alice, bob)

4. **http://your-vm-ip:8000/admin/pending/**
   - Login as: `moderator` / `moderator123`
   - Should show: 1 pending badge ("Demo Extension Contributor")

### Database Check

```bash
python manage.py shell
```

```python
from pgweb.contributors.models import Badge, Contributor
from django.contrib.auth.models import User

# Check badges
print(f"Total badges: {Badge.objects.count()}")  # Should be 5
print(f"Approved: {Badge.objects.filter(approved=True).count()}")  # Should be 4
print(f"Pending: {Badge.objects.filter(approved=False).count()}")  # Should be 1

# Check badge holders
alice = User.objects.get(username='alice')
badges = Badge.objects.filter(approved=True, holders=alice)
print(f"Alice has {badges.count()} badges")  # Should be 3

# Check profiles
print(f"Profiles: {Contributor.objects.filter(user__isnull=False).count()}")  # Should be 2
```

---

## Login Credentials

See **DEMO_CREDENTIALS.md** for the complete list, but here are the essentials:

| Username | Password | Use For |
|----------|----------|---------|
| `admin` | `admin123` | Everything |
| `moderator` | `moderator123` | Approve badges at `/admin/pending/` |
| `orgmanager1` | `manager123` | Create/manage badges |
| `alice` | `alice123` | User with badges + profile |
| `charlie` | `charlie123` | User with badges, no profile (can test profile creation) |

---

## Troubleshooting

### "relation contributors_badge does not exist"

**Problem:** Migrations weren't run

**Solution:**
```bash
python manage.py migrate contributors
```

### "No module named 'pgweb'"

**Problem:** Not in the right directory or venv not activated

**Solution:**
```bash
cd ~/pgweb  # or wherever pgweb is
source venv/bin/activate
```

### "DETAIL: Key (user_id)=(X) already exists"

**Problem:** Demo data already exists

**Solution:** The script tries to clean up, but if there's an error, manually delete:
```bash
python manage.py shell
```
```python
from django.contrib.auth.models import User
User.objects.filter(username__in=['admin', 'moderator', 'orgmanager1', 'orgmanager2', 'alice', 'bob', 'charlie']).delete()
```

Then run `setup_badge_demo_data.py` again.

### "Permission denied: ./setup_vm_database.sh"

**Solution:**
```bash
chmod +x setup_vm_database.sh
```

### Migration Already Applied

If you get "No migrations to apply" but tables don't exist:

```bash
# Check migration status
python manage.py showmigrations contributors

# If 0004 is marked [X] but table doesn't exist, fake rollback and reapply:
python manage.py migrate contributors 0003
python manage.py migrate contributors
```

---

## What Gets Created

### Users (7 total)
- 1 superuser (admin)
- 1 moderator (can access /admin/pending/)
- 2 org managers (can create badges)
- 3 badge holders (regular users)

### Organizations (3 total)
- Demo PGConf.dev (manager: orgmanager1)
- Demo PostgreSQL Extension Project (manager: orgmanager2)
- Demo PostgreSQL Company (managers: both)

### Badges (5 total)
- 4 approved (visible to everyone)
- 1 pending (only visible to admins/moderators)

### Contributor Profiles (3 total)
- alice (has profile with 3 badges)
- bob (has profile with 2 badges)
- 1 recognized major contributor (traditional system)

### Badge Holder Relationships
- alice: 3 badges
- bob: 2 badges (but pending badge won't show)
- charlie: 2 badges (but no profile, so not listed publicly)

---

## Next Steps After Setup

### Test Workflow 1: Approve Pending Badge
1. Login: `moderator` / `moderator123`
2. Go to: `/admin/pending/`
3. Click: "Demo Extension Contributor"
4. Click: "Approve"
5. Verify: Badge now visible at `/community/people/`

### Test Workflow 2: Add Badge Holder
1. Login: `orgmanager1` / `manager123`
2. Go to: `/account/edit/badges/`
3. Click: "PGConf.dev 2025 Speaker"
4. In "add_holder" field, type: `charlie@example.com`
5. Submit
6. Go to: `/community/badge/1/`
7. Result: Charlie NOT shown (no profile yet)

### Test Workflow 3: Create Profile
1. Login: `charlie` / `charlie123`
2. Go to: `/account/profile/`
3. See: "Create contributor profile" section
4. Check: "Create publicly visible profile page"
5. Fill in bio
6. Submit
7. Go to: `/community/people/charlie/`
8. Result: Profile now visible with badges!

---

## Files Reference

- **setup_badge_demo_data.py** - Demo data creation script
- **setup_vm_database.sh** - Automated setup (migrations + data)
- **DEMO_CREDENTIALS.md** - Quick reference with all logins and workflows
- **BADGE_IMPLEMENTATION_COMPARISON.md** - Technical comparison of implementations
- **REVIEW_SUMMARY.md** - Executive summary of review

---

## Important Notes

⚠️ **This is demo data only!** 
- All emails use example.com
- Passwords are simple (admin123, etc.)
- Organizations are prefixed with "Demo"

⚠️ **Known Issue:**
- User bio edits go live without moderation (Magnus's concern)
- Test this: Login as alice, edit contribution field, spam goes live immediately

✅ **For Production:**
- Use real passwords
- Don't include demo organizations
- Consider adding moderation for contributor profiles
- Set up email notifications for badge holder additions

---

## Getting Help

If you run into issues:

1. Check migration status: `python manage.py showmigrations contributors`
2. Check database: `python manage.py dbshell` then `\dt contributors_*`
3. Check logs: Look for error messages in terminal
4. Check file: `DEMO_CREDENTIALS.md` for expected behavior

---

**Last Updated:** 2026-01-20
**For:** Contributors Committee badge system (badges3 branch)
