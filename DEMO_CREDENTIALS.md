# Badge System Demo - Quick Reference Card

## 🔑 Login Credentials

| Role | Username | Password | Can Do |
|------|----------|----------|--------|
| **Superuser** | `admin` | `admin123` | Everything |
| **Moderator** | `moderator` | `moderator123` | Approve badges at `/admin/pending/` |
| **Org Manager** | `orgmanager1` | `manager123` | Create badges, add holders (PGConf.dev) |
| **Org Manager** | `orgmanager2` | `manager123` | Create badges, add holders (Extension Project) |
| **Badge Holder** | `alice` | `alice123` | Has 3 badges + profile page |
| **Badge Holder** | `bob` | `bob123` | Has 2 badges + profile page |
| **Badge Holder** | `charlie` | `charlie123` | Has 2 badges, NO profile |

---

## 🏆 Sample Badges Created

| Badge | Org | Status | Holders |
|-------|-----|--------|---------|
| PGConf.dev 2025 Speaker | Demo PGConf.dev | ✅ Approved | alice, bob |
| PGConf.dev 2025 Volunteer | Demo PGConf.dev | ✅ Approved | alice, charlie |
| PostgreSQL 18 Contributor | Demo PG Company | ✅ Approved | alice, bob, charlie |
| Community Moderator 2025 | Demo PG Company | ✅ Approved | charlie |
| Demo Extension Contributor | Demo Extension Project | ⚠️ PENDING | bob (hidden) |

---

## 🔗 Important URLs

### Public Pages
- `/community/people/` - All badge holders and badges
- `/community/people/alice/` - Alice's profile (3 badges)
- `/community/people/bob/` - Bob's profile (2 badges shown)
- `/community/badge/1/` - Badge detail page (PGConf.dev Speaker)
- `/community/contributors/` - Traditional recognized contributors

### Account Management
- `/account/profile/` - Edit your profile, create contributor page
- `/account/edit/badges/` - Manage your organization's badges
- `/account/edit/badges/1/` - Edit specific badge

### Admin
- `/admin/` - Django admin
- `/admin/pending/` - Approve pending badges (moderator only)

---

## 📖 Test Workflows

### Workflow 1: Org Manager Creates Badge
1. Login: `orgmanager1` / `manager123`
2. Go to: `/account/edit/badges/`
3. Click: **"Submit new contributor badge"**
4. Fill in:
   - Badge: "PGConf.dev 2026 Attendee"
   - Description: "Attended PGConf.dev 2026"
   - URL: https://pgconf.dev/2026
   - Image: (leave blank or use placeholder URL)
   - Contact: attendees@pgconf.dev
   - Organisation: Demo PGConf.dev
5. Submit
6. **Result:** Badge created, status = PENDING

### Workflow 2: Moderator Approves Badge
1. Login: `moderator` / `moderator123`
2. Go to: `/admin/pending/`
3. Look for: **"Contributor badge"** section
4. Click: The pending badge
5. Click: **"Approve"** button
6. **Result:** Badge now visible at `/community/badge/X/`

### Workflow 3: Add Badge Holders
1. Login: `orgmanager1` / `manager123`
2. Go to: `/account/edit/badges/1/` (edit existing badge)
3. Scroll to: **"Badge Holders"** section
4. In "add_holder" field, enter: `alice@example.com bob@example.com`
5. Submit
6. **Result:** Alice and Bob added as badge holders

### Workflow 4: Remove Badge Holder
1. Login: `orgmanager1` / `manager123`
2. Go to: `/account/edit/badges/1/`
3. In "remove_holder", select user(s) to remove
4. Submit
5. **Result:** User removed from badge holders

### Workflow 5: User Creates Profile
1. Login: `charlie` / `charlie123`
2. Go to: `/account/profile/`
3. See: **"Create contributor profile"** section (because charlie has badges)
4. Check: ☑ "Create publicly visible profile page"
5. Fill in bio info if you want
6. Submit
7. **Result:** Profile created at `/community/people/charlie/`

### Workflow 6: User Edits Profile Bio
1. Login: `alice` / `alice123` (already has profile)
2. Go to: `/account/profile/`
3. Edit: "Describe what you did in the PostgreSQL community" field
4. Submit
5. **Result:** Bio updated on `/community/people/alice/`
6. ⚠️ **NOTE:** No moderation (this is the issue Magnus raised!)

---

## 🧪 Edge Cases to Test

### Test 1: Badge Not Visible Until Approved
- Go to: `/community/people/` (not logged in)
- **Expected:** "Demo Extension Contributor" badge NOT shown
- Login as: `moderator`, approve badge at `/admin/pending/`
- Refresh: `/community/people/`
- **Expected:** Badge now visible

### Test 2: Badge Holders Without Profiles Not Listed
- Login: `orgmanager1`
- Edit badge #1, add holder: `charlie@example.com`
- Go to: `/community/badge/1/`
- **Expected:** Charlie NOT shown in holders list (has no profile)
- Login: `charlie`, create profile at `/account/profile/`
- Go to: `/community/badge/1/`
- **Expected:** Charlie NOW shown in holders list

### Test 3: User Can't Create Profile Without Badges
- Create new user (or use one without badges)
- Login, go to: `/account/profile/`
- **Expected:** NO "Create contributor profile" section shown

### Test 4: Org Manager Can Only Edit Their Org's Badges
- Login: `orgmanager1` (manages PGConf.dev)
- Go to: `/account/edit/badges/`
- **Expected:** Only see PGConf.dev badges, not Extension Project badges

### Test 5: Multiple Org Managers
- Login: `orgmanager1` (manages PGConf.dev + PG Company)
- Go to: `/account/edit/badges/`
- **Expected:** See badges from BOTH organizations

---

## 🐛 Known Issues (from review)

### Issue 1: No Moderation for User Bios
**Problem:** Users can edit contributor bio and it goes live immediately

**Test:**
1. Login: `alice` / `alice123`
2. Go to: `/account/profile/`
3. Change "contribution" to: "SPAM! Buy my product!"
4. Submit
5. Go to: `/community/people/alice/`
6. **Current:** Spam text shown immediately ❌
7. **Should:** Require moderator approval ✅

**This is the critical issue Magnus raised!**

### Issue 2: No User Notification When Added as Badge Holder
**Problem:** Org manager adds user, but user isn't notified

**Test:**
1. Create new user: `newuser` / `newuser123`
2. Login as: `orgmanager1`
3. Add `newuser@example.com` to badge #1
4. Login as: `newuser`
5. **Current:** No notification, user has to discover they have badges
6. **Should:** Email sent: "You've been awarded X badge!"

### Issue 3: No Opt-Out for Badge Holders
**Problem:** User can't decline being listed as badge holder

**Current:** Once org manager adds you, you're listed (if you create profile)
**Should:** User can opt-out or hide specific badges

---

## 💡 Quick Tips

### For Org Managers:
- Badge images should be square (150x150px recommended)
- Use placeholder images for testing: `https://via.placeholder.com/150/COLOR/FFFFFF?text=TEXT`
- You can add holders even before badge is approved (they just won't show publicly)
- To add multiple holders: Separate emails with spaces

### For Moderators:
- Pending badges appear under "Contributor badge" at `/admin/pending/`
- Click badge name → Click "Approve" button
- You can also access via Django admin: `/admin/contributors/badge/`

### For Badge Holders:
- You must create a profile to be publicly listed as badge holder
- Your profile can be edited at `/account/profile/` anytime
- Your badges automatically show on your profile page
- Profile URL format: `/community/people/{your-username}/`

---

## 🔧 Troubleshooting

### "You don't have permission to access /admin/pending/"
- **Solution:** User needs `is_staff=True` AND be in "pgweb moderators" group
- **Fix:** Login as admin, go to `/admin/auth/user/{id}/`, check both settings

### "Badge doesn't show on /community/people/"
- **Check 1:** Is badge approved? (approved=True)
- **Check 2:** Do holders have profiles? (Contributor record with user link)

### "Can't see badge in /account/edit/badges/"
- **Check:** Are you a manager of the organization that owns the badge?
- **Fix:** Login as admin, go to `/admin/core/organisation/`, add user as manager

### "Badge holder not showing on badge page"
- **Reason:** User doesn't have a Contributor profile
- **Fix:** User needs to login, go to `/account/profile/`, check "Create profile"

---

## 📊 Database Quick Check

```python
# python manage.py shell

from django.contrib.auth.models import User
from pgweb.contributors.models import Badge, Contributor

# Count badges
print(f"Total badges: {Badge.objects.count()}")
print(f"Approved badges: {Badge.objects.filter(approved=True).count()}")
print(f"Pending badges: {Badge.objects.filter(approved=False).count()}")

# Count badge holders
for badge in Badge.objects.all():
    print(f"{badge.badge}: {badge.holders.count()} holders")

# Count profiles
print(f"Total contributor profiles: {Contributor.objects.count()}")
print(f"Profiles with user accounts: {Contributor.objects.filter(user__isnull=False).count()}")

# Show alice's badges
alice = User.objects.get(username='alice')
badges = Badge.objects.filter(approved=True, holders=alice)
print(f"Alice has {badges.count()} badges")
```

---

**Generated by:** `setup_badge_demo_data.py`
**Last updated:** 2026-01-20
