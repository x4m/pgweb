# Badge Implementation Review - Executive Summary

## The Question
Contributors Committee submitted a badge implementation. Should we use it instead of what we built?

## Quick Answer
**Yes, use theirs** - but add moderation for user-editable profiles first.

---

## What's Different?

### Our Implementation (badges2)
**User Journey:** Browse badges → Click "Claim" → Write message → Org approves → Badge appears on profile

```
User: "I volunteered at PGConf!"
[Submits claim with message]
↓
Org Manager: Reviews claim → Approves/Rejects
↓
Badge shows on user's page
```

### Contributors Committee (badges3)
**User Journey:** Email org contact → Org manager adds you by email → Opt-in to create profile page

```
User: Emails pgconf-organizers@example.com
↓
Org Manager: Adds user's email to badge holders list
↓
User: Gets notified, visits /account/profile/, checks "Create profile" box
↓
Profile appears at /community/people/username/
```

---

## Key Differences in 3 Points

1. **Who initiates:** 
   - Ours: User claims badge
   - Theirs: Org manager adds user

2. **Integration:**
   - Ours: Standalone in `/account/badges/`
   - Theirs: Part of contributor system at `/community/people/`

3. **Badge design:**
   - Ours: Font Awesome icons + colors (e.g., 🏆 gold)
   - Theirs: Custom images (e.g., conference logo)

---

## Why Use Theirs?

1. ✅ **Community backing** - Contributors Committee designed it
2. ✅ **Solves bigger problem** - Not just badges, but contributor recognition
3. ✅ **Simpler data model** - One table vs three
4. ✅ **Professional images** - Custom badge graphics
5. ✅ **Better integration** - Works with existing contributor system

---

## Critical Issue to Fix First

**Problem:** User-editable bio text gets published without moderation

```python
# In their implementation:
contributor.contribution = "Whatever I want to say..."  # Goes live immediately!
```

**Magnus said:**
> "If it's data published by users... it *must* be moderated. We will definitely not open 
> up another venue for spam. If it's things that not-specifically-approved users can add, 
> then it *must* be moderated."

**Solution:** Add moderation for Contributor profile edits:
```python
class Contributor(TwostateModerateModel):  # Add moderation!
    contribution = TextField()  # Requires approval before published
    approved = BooleanField(default=False)
```

---

## What Needs to Happen

### Before Deploying badges3:

1. **Add Moderation** ⚠️ CRITICAL
   - Make Contributor.contribution field require approval
   - Or make entire profile creation require moderation
   - Send notifications to moderators

2. **Create Migrations** ⚠️ REQUIRED
   - Make Contributor.ctype nullable
   - Create Badge table and holders ManyToMany
   - Test with existing data

3. **Notify Users** 📧 RECOMMENDED
   - When added as badge holder, send email
   - Let them opt-out if they don't want to be listed

4. **Document Image Workflow** 📝 NICE-TO-HAVE
   - Format: PNG/SVG, 150x150px
   - How to submit: Email contributors@postgresql.org
   - Contributors team adds to git

5. **Test Edge Cases** 🧪 RECOMMENDED
   - What if org manager adds fake email?
   - What if user wants badge removed?
   - What if badge image is inappropriate?

---

## Migration Path

### If using badges3:

```bash
# Current state: On badges3 branch (Contributors Committee patch applied)

# 1. Add moderation to Contributor model
# Edit: pgweb/contributors/models.py

# 2. Create migrations
python manage.py makemigrations contributors

# 3. Test locally
python manage.py migrate
# ... test workflow ...

# 4. Deploy without navigation links (test in production)
# Comment out in pgweb/util/contexts.py

# 5. Once confirmed working, enable navigation links
```

### If keeping our implementation (badges2):

```bash
# Switch back to badges2
git checkout badges2

# Push to production
git push production master

# Simple deployment, already has migrations
```

---

## Recommendation

**Use Contributors Committee implementation (badges3)** with moderation additions.

**Reasoning:**
- It's community-designed and backed
- Solves a broader problem (contributor recognition)
- Simpler architecture
- More professional appearance

**But first:**
- Add moderation for user-editable profiles
- Create and test migrations
- Consider user notification when added as badge holder

**Timeline:**
- If urgent: Deploy badges2 (ready now, low risk)
- If can wait 1-2 weeks: Deploy badges3 with moderation (better long-term)

---

## One-Line Summary

**Use the Contributors Committee patch, but add moderation for user profiles first to address Magnus's spam concerns.**
