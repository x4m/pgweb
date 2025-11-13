# Badge System for PostgreSQL Community

## Overview
The badge system allows administrators to recognize community members' achievements and contributions by awarding them virtual badges that are displayed on their public profile pages.

## Features Implemented

### 1. Badge Management
- **Badge Model**: Administrators can create badges with:
  - Name (e.g., "First Commit", "First Review", "First Revert")
  - Description (what the badge represents)
  - Icon (Font Awesome icon class like `fa-trophy`, `fa-star`, `fa-code`)
  - Color (hex color code like `#FFD700` for gold)
  - Display order (for sorting badges)

### 2. User Badge Awards
- **UserBadge Model**: Tracks badge assignments with:
  - User who received the badge
  - Which badge was awarded
  - When it was awarded
  - Who awarded it (admin user)
  - Optional note about the award

### 3. User Interface

#### Public Badge Page
- **URL**: `/account/badges/<username>/`
- Displays all badges earned by a user
- Shows badge icon, name, description, and award date
- Shows who awarded the badge
- Includes optional notes from the admin
- Summary of total badges earned

#### Account Dashboard
- Badge count displayed on user's account home page
- Direct link to view their badges
- Encouragement message if no badges yet

### 4. Admin Interface
- **Badge Admin**: Create, edit, and manage badge types
  - List view shows name, icon, color, and order
  - Can reorder badges by changing the order field
  - Search by name or description

- **User Badge Admin**: Award badges to users
  - Assign badges to specific users
  - Add optional notes
  - Automatically records who awarded it
  - Filter by badge type and date
  - Search by username or badge name

## URLs

| URL | Description | Access |
|-----|-------------|--------|
| `/account/badges/<username>/` | View a user's badges | Public |
| `/account/` | User's account dashboard (shows badge count) | Authenticated users |
| `/admin/account/badge/` | Manage badge types | Admin only |
| `/admin/account/userbadge/` | Award badges to users | Admin only |

## Database Schema

### Badge Model
```python
- name: CharField (unique, max 100 chars)
- description: TextField
- icon: CharField (Font Awesome class, max 50 chars)
- color: CharField (hex color, max 20 chars)
- order: IntegerField (for sorting)
```

### UserBadge Model
```python
- user: ForeignKey to User
- badge: ForeignKey to Badge
- awarded_at: DateTimeField (auto-set)
- awarded_by: ForeignKey to User (the admin)
- note: TextField (optional)
- Unique constraint: (user, badge) - can't award same badge twice
```

## Sample Badges Created

The system comes with 5 pre-created badges:

1. **First Commit** 🟢
   - Icon: `fa-code`
   - Color: Green (#4CAF50)
   - Description: Made their first commit to the PostgreSQL codebase

2. **First Review** 🔵
   - Icon: `fa-search`
   - Color: Blue (#2196F3)
   - Description: Completed their first code review

3. **First Revert** 🟠
   - Icon: `fa-undo`
   - Color: Orange (#FF9800)
   - Description: Had their first commit reverted (it happens to the best!)

4. **Bug Hunter** 🔴
   - Icon: `fa-bug`
   - Color: Red (#F44336)
   - Description: Found and reported a critical bug

5. **Documentation Hero** 🟣
   - Icon: `fa-book`
   - Color: Purple (#9C27B0)
   - Description: Made significant contributions to documentation

## How to Use

### For Administrators

#### Create a New Badge
1. Go to `/admin/account/badge/`
2. Click "Add Badge"
3. Fill in the details:
   - Name (e.g., "10 Year Contributor")
   - Description
   - Icon (Font Awesome class, browse at https://fontawesome.com/icons)
   - Color (hex code)
   - Order (lower numbers appear first)
4. Save

#### Award a Badge to a User
1. Go to `/admin/account/userbadge/`
2. Click "Add User Badge"
3. Select the user
4. Select the badge
5. Optionally add a note
6. Save (your username will be automatically recorded as the awarder)

### For Users

#### View Your Badges
1. Log in to your account
2. Go to `/account/`
3. You'll see your badge count in a highlighted box
4. Click "View Your Badges" to see your full badge collection

#### View Another User's Badges
- Visit `/account/badges/<their-username>/`
- Anyone can view any user's badges (public page)

## Technical Details

### Files Modified/Created

**Models**: `/pgweb/account/models.py`
- Added Badge model
- Added UserBadge model

**Admin**: `/pgweb/account/admin.py`
- Added BadgeAdmin class
- Added UserBadgeAdmin class

**Views**: `/pgweb/account/views.py`
- Modified `home()` to include badge count
- Added `user_badges()` view for displaying badges

**URLs**: `/pgweb/account/urls.py`
- Added route for `/account/badges/<username>/`

**Templates**:
- `/templates/account/badges.html` - Badge display page
- `/templates/account/index.html` - Modified to show badge count

**Database Migration**:
- `/pgweb/account/migrations/0011_badge_userbadge.py`

## Future Enhancements

Potential features to add:
- Badge categories (Contribution, Community, Special)
- Badge rarity levels (Common, Rare, Epic, Legendary)
- Badge unlock conditions (automatic awarding)
- Leaderboard showing users with most badges
- Badge notifications (email when awarded)
- Badge sharing on social media
- Badge revocation (remove awarded badges)
- Public badge gallery page
- Badge statistics and analytics

## Testing

The system has been tested with:
- Creating 5 sample badges
- Awarding 3 badges to the admin user
- Viewing badges on the profile page
- Checking badge count on account dashboard
- All linter checks pass
- Database migrations applied successfully

## Notes

- Badges can only be awarded by administrators through the admin interface
- Each badge can only be awarded once to a user (enforced by unique constraint)
- All badge icons use Font Awesome, which is already included in pgweb
- Badge pages are public - anyone can view any user's badges
- The system integrates seamlessly with existing pgweb authentication

