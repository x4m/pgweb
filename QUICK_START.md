# Quick Start Guide - PostgreSQL Website Badge System

## ✅ Setup Complete!

The PostgreSQL website is running with the new badge system fully integrated.

## 🚀 Access the Website

**Main Site**: http://localhost:8000

**Admin Panel**: http://localhost:8000/admin/
- Username: `admin`
- Password: `admin123`

## 🎖️ Badge System Features

### View Badges (Public)
**URL**: http://localhost:8000/account/badges/admin/

This shows the admin user's badges. Try it - we've already awarded 3 sample badges:
- ✅ First Commit (green code icon)
- ✅ First Review (blue search icon)  
- ✅ Bug Hunter (red bug icon)

### Manage Badges (Admin Only)

1. **View All Badges**: http://localhost:8000/admin/account/badge/
   - See all available badge types
   - Create new badges
   - Edit existing ones

2. **Award Badges to Users**: http://localhost:8000/admin/account/userbadge/
   - Select a user
   - Choose a badge
   - Add optional note
   - Save to award

### User Account Dashboard
**URL**: http://localhost:8000/account/ (requires login)
- Shows badge count
- Link to view your badges

## 📝 How to Award a Badge

1. Log in to admin: http://localhost:8000/admin/
2. Go to "User badges" section
3. Click "Add User Badge"
4. Fill in:
   - **User**: Search and select the user
   - **Badge**: Choose from existing badges
   - **Note**: (optional) Add why they earned it
5. Click "Save"

The user will now see this badge on their profile!

## 🎨 How to Create a New Badge

1. Log in to admin: http://localhost:8000/admin/
2. Go to "Badges" section  
3. Click "Add Badge"
4. Fill in:
   - **Name**: e.g., "10 Year Contributor"
   - **Description**: What this badge means
   - **Icon**: Font Awesome class (e.g., `fa-star`, `fa-trophy`, `fa-award`)
     - Browse icons: https://fontawesome.com/icons
   - **Color**: Hex color code (e.g., `#FFD700` for gold)
   - **Order**: Lower numbers appear first (e.g., 10, 20, 30)
5. Click "Save"

## 🏆 Sample Badges Already Created

We've pre-created 5 badges for you:

| Badge | Icon | Color | Description |
|-------|------|-------|-------------|
| First Commit | `fa-code` | Green | Made their first commit |
| First Review | `fa-search` | Blue | Completed first code review |
| First Revert | `fa-undo` | Orange | Had first commit reverted |
| Bug Hunter | `fa-bug` | Red | Found a critical bug |
| Documentation Hero | `fa-book` | Purple | Significant docs contributions |

## 🛠️ Development Commands

### Start the Server
```bash
cd /Users/x4mmm/workshop/pgweb
source venv/bin/activate
python manage.py runserver
```

### Create a New User (for testing)
```bash
source venv/bin/activate
python manage.py createsuperuser
```

### Access PostgreSQL Database
```bash
psql pgweb
```

## 📁 Key Files

- **Models**: `pgweb/account/models.py` (Badge, UserBadge)
- **Admin**: `pgweb/account/admin.py` (BadgeAdmin, UserBadgeAdmin)
- **Views**: `pgweb/account/views.py` (user_badges view)
- **Templates**: `templates/account/badges.html`
- **URLs**: `pgweb/account/urls.py`

## 📖 Full Documentation

See `BADGES_FEATURE.md` for complete technical documentation.

## 🐛 Troubleshooting

**Server not running?**
```bash
cd /Users/x4mmm/workshop/pgweb
source venv/bin/activate
python manage.py runserver
```

**Database issues?**
```bash
python manage.py migrate
```

**Create test data?**
```bash
python manage.py shell
from django.contrib.auth.models import User
from pgweb.account.models import Badge, UserBadge
# ... create badges and award them
```

## 🎯 What You Can Do Now

1. ✅ View badges: http://localhost:8000/account/badges/admin/
2. ✅ Log in to admin: http://localhost:8000/admin/
3. ✅ Create new badge types
4. ✅ Award badges to users
5. ✅ Create additional users and award them badges
6. ✅ Customize badge icons and colors

Enjoy your new badge system! 🎉

