# Badge System Implementation Comparison

## Overview

Two different implementations of a badge system for PostgreSQL.org:

1. **Our Implementation** (`badges2` branch) - Organization-based with user claim/approval workflow
2. **Contributors Committee Implementation** (`badges3` branch) - Organization managers directly add badge holders

---

## Key Differences Summary

| Aspect | Our Implementation (badges2) | Contributors Committee (badges3) |
|--------|------------------------------|-----------------------------------|
| **Location** | `pgweb/account/` app | `pgweb/contributors/` app |
| **User Workflow** | Users browse & claim badges → Org approves | Org managers directly add users by email |
| **Badge Approval** | Badges need admin approval before claimable | Badges need admin approval before visible |
| **Data Model** | Badge, BadgeClaim, UserBadge (3 models) | Badge with ManyToMany holders (1 model) |
| **URLs** | `/account/badges/...` | `/community/people/...`, `/community/badge/...` |
| **Badge Design** | Icon + Color (Font Awesome) | Image file (hosted on pgweb) |
| **Profile Pages** | User badge pages under `/account/badges/{username}/` | Contributor profiles under `/community/people/{username}/` |
| **Integration** | Standalone badge system | Integrated with Contributor system |
| **Migrations** | Included (2 migrations) | Not included in patch yet |

---

## Detailed Comparison

### 1. Architecture & Data Model

#### Our Implementation (badges2)
```python
# Location: pgweb/account/models.py

class Badge(models.Model):
    name = CharField(max_length=200)
    description = TextField()
    organisation = ForeignKey(Organisation)
    icon = CharField(max_length=50, default='fa-trophy')  # Font Awesome
    color = CharField(max_length=20, default='#FFD700')   # Hex color
    approved = BooleanField(default=False)  # Site admin approval
    active = BooleanField(default=True)     # Site admin only
    created_at = DateTimeField(auto_now_add=True)
    created_by = ForeignKey(User)

class BadgeClaim(models.Model):
    user = ForeignKey(User)
    badge = ForeignKey(Badge)
    status = CharField  # PENDING, APPROVED, REJECTED
    claimed_at = DateTimeField(auto_now_add=True)
    message = TextField()  # User's claim message
    reviewed_at = DateTimeField()
    reviewed_by = ForeignKey(User)
    review_note = TextField()  # Org manager's response

class UserBadge(models.Model):
    user = ForeignKey(User)
    badge = ForeignKey(Badge)
    claim = OneToOneField(BadgeClaim)  # Link to approved claim
    awarded_at = DateTimeField(auto_now_add=True)
```

**Workflow:**
1. Org manager creates badge → Status: Pending Approval
2. Site admin approves badge → Badge visible to users
3. User browses available badges → Submits claim with message
4. Org manager reviews claim → Approves/Rejects
5. If approved → UserBadge created → Shows on user's profile

#### Contributors Committee Implementation (badges3)
```python
# Location: pgweb/contributors/models.py

class Badge(TwostateModerateModel):  # Has approved field built-in
    org = ForeignKey(Organisation)
    badge = CharField(max_length=32, unique=True)  # Badge title
    description = TextField()
    url = URLField()  # URL for the contribution
    image = CharField(max_length=100)  # Path to image file
    contact = CharField(max_length=100)  # How to request badge
    holders = ManyToManyField(User, blank=True)  # Direct relationship
    sortorder = IntegerField(default=100)

class Contributor(models.Model):  # Extended existing model
    ctype = ForeignKey(ContributorType, null=True, blank=True)  # Now nullable!
    firstname = CharField(max_length=100)
    lastname = CharField(max_length=100)
    email = EmailField()
    company = CharField()
    contribution = TextField()  # Bio/"what you did"
    user = ForeignKey(User)  # Link to user account
```

**Workflow:**
1. Org manager creates badge → Status: Pending Approval
2. Site admin approves badge → Badge visible
3. Org manager adds badge holders by entering email addresses
4. Badge holder receives notification → No explicit acceptance needed
5. Badge holder can opt-in to create public profile page
6. Profile shows under `/community/people/{username}/`

### 2. User Experience

#### Our Implementation (badges2)
**User Actions:**
- Browse available badges at `/account/badges/`
- Click "Claim Badge" → Fill form with message explaining eligibility
- View claim status at `/account/badges/my-claims/`
- Once approved, badge shows on `/account/badges/{username}/`

**Org Manager Actions:**
- Create/edit badges at `/account/org/badges/`
- Review claims at `/account/org/claims/`
- Filter by status (Pending/Approved/Rejected)
- Approve/reject with review note

**Pages:**
- `/account/badges/` - Browse all available badges
- `/account/badges/claim/{id}/` - Claim a badge
- `/account/badges/my-claims/` - View your claims
- `/account/badges/{username}/` - User's badge profile
- `/account/org/badges/` - Manage org's badges
- `/account/org/badges/create/` - Create new badge
- `/account/org/badges/edit/{id}/` - Edit badge
- `/account/org/claims/` - Review claims

#### Contributors Committee Implementation (badges3)
**User Actions:**
- Users don't proactively claim badges
- Users email the badge contact address (listed on badge page)
- Org manager manually adds them
- Users opt-in to create profile via `/account/profile/` checkbox
- Profile shows at `/community/people/{username}/`

**Org Manager Actions:**
- Create/edit badges through existing "Submit" workflow
- Add holders: Enter email addresses in "add_holder" field
- Remove holders: Select from "remove_holder" multi-select
- Notifications sent to `NOTIFICATION_EMAIL` on changes

**Pages:**
- `/community/people/` - All badge holders and badges
- `/community/people/{username}/` - User's contributor profile
- `/community/badge/{id}/` - Badge page with holders
- `/account/edit/badges/{id}/` - Edit badge (via existing account/edit system)

### 3. Moderation & Permissions

#### Our Implementation (badges2)
**Site Admin:**
- Approves new badges via `/admin/pending/`
- Can set `active` status (on/off switch for claiming)
- Can approve/reject badge claims (if they want)

**Org Manager:**
- Can create badges (but can't set active status)
- Can edit badge name, description, icon, color
- Can review badge claims (approve/reject)
- Cannot directly add badge holders

**User:**
- Can browse approved & active badges
- Can claim badges (with message)
- Can view their claim status
- Public profile shows approved badges

#### Contributors Committee Implementation (badges3)
**Site Admin:**
- Approves new badges via `/admin/pending/`
- Can edit all badge fields
- Receives notifications when holders are added/removed

**Org Manager:**
- Can create badges
- Can edit all badge fields (including moderation_fields after approval)
- Can directly add/remove badge holders by email
- No claim review needed

**User:**
- Passive recipient (org manager adds them)
- Can opt-in to create public profile
- Can edit contributor bio/details
- Public profile shows badges (if opt-in checked)

### 4. Badge Representation

#### Our Implementation (badges2)
```html
<i class="fa fa-trophy" style="color: #FFD700;"></i> Badge Name
```
- Uses Font Awesome icons
- Customizable color (hex code)
- No image upload needed
- Instant visual feedback
- Examples: `fa-trophy`, `fa-star`, `fa-award`, `fa-code`, `fa-microphone`

#### Contributors Committee Implementation (badges3)
```html
<img src="/media/badges/pgconf-eu-2025.png" alt="PGConf.EU 2025">
```
- Uses image files stored in `media/badges/`
- Org manager emails image to contributors@postgresql.org
- Contributors team manually adds image to git
- More professional/custom appearance
- Requires manual workflow for images

### 5. Integration with Existing Systems

#### Our Implementation (badges2)
- **Standalone**: Badge system is independent in `pgweb/account/`
- **No changes** to Contributor model
- **New navigation** section added for badges
- **Minimal impact** on existing code
- **Easy to revert** if needed

#### Contributors Committee Implementation (badges3)
- **Integrated**: Badges are part of contributor system
- **Modified Contributor model**: `ctype` now nullable
- **Extends existing** "recognized contributors" concept
- **Uses existing** submission/moderation workflow
- **Profile pages** replace/extend existing contributor listing
- **Navigation changes** to add "People" section

### 6. Melanie's Original Request

From the email thread:
> "The idea was to have the badges be created by organizations -- like PGConf.dev 2025 Volunteer. 
> Then people can apply to have that badge and the team that proposed that badge can approve that person 
> if they did in fact volunteer"

**Our Implementation:** ✅ Matches exactly
- Organizations create badges
- Users apply/claim badges
- Team approves individual applications
- Clear approval workflow

**Contributors Committee:** ⚠️ Different interpretation
- Organizations create badges
- Organizations directly add holders (no user application)
- Users contact org via email (external to system)
- Assumes org managers are trusted to add legitimate holders

### 7. Moderation Discussion from Email Thread

**Magnus's Concern:**
> "If it's data published by users where we have at one point added them to the contributors list 
> and therefore pre-moderated to some point that is reasonable. But allowing random people to add 
> records and then edit them and then it turns out to be published is going to be a hard no"

**Contributors Committee Response:**
> "The moderation part is that people have to convince a badge-issuing organisation to add their 
> pg.o account as badge holder. This is possibly a lot of organisations and people, but everyone 
> involved should be a recognised community member."

**Analysis:**
- **Our Implementation:** Badge claims provide a moderation point (org reviews each claim)
- **Contributors Committee:** Assumes org managers are trustworthy gatekeepers
- **Issue:** Contributor bio/profile content is user-editable without moderation in badges3
- **Solution Mentioned:** Add moderation for contributor profile edits (TwostateModerateModel for Contributor?)

---

## Migration Considerations

### Our Implementation (badges2)
**Database Changes:**
```sql
-- 0011_badge_claim_system.py
CREATE TABLE account_badge (...);
CREATE TABLE account_badgeclaim (...);
CREATE TABLE account_userbadge (...);

-- 0012_add_badge_approval.py  
ALTER TABLE account_badge ADD approved BOOLEAN DEFAULT FALSE;
ALTER TABLE account_badge ALTER COLUMN active SET help_text='Site admin only...';
```

**Status:** ✅ Migrations created and tested
**Data:** Can start fresh or import existing badges

### Contributors Committee Implementation (badges3)
**Database Changes:**
```sql
-- Not yet created (mentioned in email: "will do that after review")
ALTER TABLE contributors_contributor ALTER COLUMN ctype DROP NOT NULL;
ALTER TABLE contributors_contributor ALTER COLUMN contribution SET help_text='...';
CREATE TABLE contributors_badge (...);
CREATE TABLE contributors_badge_holders (ManyToMany table);
```

**Status:** ⚠️ Migrations not included in patch
**Data:** Affects existing Contributor records (make ctype nullable)

---

## Pros & Cons

### Our Implementation (badges2)

**Pros:**
✅ Matches Melanie's original request exactly
✅ Clear user claim → approval workflow
✅ Audit trail (who claimed when, who approved, review notes)
✅ Self-service for users (browse & claim)
✅ Standalone (easy to revert, no risk to existing data)
✅ No external dependencies (no image management)
✅ Font Awesome icons are flexible and instant
✅ Migrations included and tested
✅ Three-stage filter (badge approval + claim approval = moderation)

**Cons:**
❌ More complex data model (3 tables vs 1)
❌ More code (views, forms, templates for claim workflow)
❌ Font Awesome icons may look less professional than custom images
❌ Not integrated with contributor system
❌ Doesn't solve the "recognized contributor" listing problem

### Contributors Committee Implementation (badges3)

**Pros:**
✅ Simpler data model (1 table with ManyToMany)
✅ Less code overall
✅ Integrated with existing contributor system
✅ Solves "recognized contributor" listings
✅ Professional custom badge images
✅ Uses existing submission/moderation workflow
✅ Backed by Contributors Committee (community buy-in)
✅ Addresses broader community recognition problem

**Cons:**
❌ Doesn't match Melanie's original request (no user claim workflow)
❌ External workflow (users email to request, org manager manually adds)
❌ Image management requires manual work (email → git → update DB)
❌ Modifies existing Contributor model (riskier)
❌ No audit trail for badge holder additions
❌ Migrations not included yet
❌ Contributor profiles need moderation (mentioned but not implemented)
❌ Org managers can add anyone without per-person approval

---

## Recommendations

### Option 1: Use Contributors Committee Implementation (badges3)
**When:** If the goal is to recognize community members broadly and integrate with contributor system

**Action Items:**
1. ✅ The patch is well-designed and community-backed
2. ⚠️ **CRITICAL:** Add moderation for Contributor.contribution field (bio text)
   - Make Contributor use TwostateModerateModel or similar
   - Or add approval workflow for profile creation/edits
3. ⚠️ Create migrations carefully (test ctype nullable change)
4. ⚠️ Define image management workflow (who adds images, format requirements)
5. ⚠️ Consider notification to users when added as badge holder
6. ⚠️ Consider opt-out mechanism for badge holders who don't want to be listed

**Magnus's concerns addressed:**
- Need to add moderation for contributor profile edits
- Consider making holder additions require notification/acceptance

### Option 2: Use Our Implementation (badges2)
**When:** If user claim/approval workflow is essential and badges should be standalone

**Action Items:**
1. ✅ Implementation is complete and tested
2. ✅ Migrations are ready
3. ⚠️ Consider adding image support (optional)
4. ⚠️ Consider how this integrates with future contributor recognition
5. ⚠️ May need to explain to Contributors Committee why their approach wasn't used

### Option 3: Hybrid Approach
**When:** Want both workflows available

**Possible design:**
1. Use Contributors Committee's data model (Badge in contributors app)
2. Add our claim/approval workflow as optional
3. Badge has setting: "Allow user claims" vs "Organization manages holders"
4. Best of both worlds but more complexity

---

## Technical Review Comments

### Contributors Committee Patch (badges3)

**Code Quality:** 
- ✅ Well-structured, follows Django conventions
- ✅ Good use of TwostateModerateModel
- ✅ Clean integration with existing submission workflow

**Security/Moderation Concerns:**
- ⚠️ Contributor.contribution (bio) is user-editable and published without moderation
- ⚠️ No per-holder approval (org manager can add anyone)
- ⚠️ Consider: What if an org manager goes rogue?

**Suggested Changes:**
1. Add `send_notification = True` and `purge_urls` to Contributor if profile is public
2. Consider making Contributor.contribution changes require moderation
3. Add notification email when user is added as badge holder
4. Add opt-out: Badge holder can decline being listed
5. Create migrations and test with existing data
6. Document image file format/size requirements

**Code Improvements:**
```python
# In BadgeForm.save():
# Currently: Directly adds holders without user notification
# Consider: Send email to user notifying them they've been added
if 'add_holder' in self.cleaned_data and self.cleaned_data['add_holder']:
    for u in self.cleaned_data['add_holder'].split():
        user = User.objects.get(email=u.lower())
        model.holders.add(user)
        # ADD: Send notification email to user
        send_simple_mail(
            settings.NOTIFICATION_FROM,
            user.email,
            f"You've been awarded the {model.badge} badge",
            f"Your account has been added as a holder of the {model.badge} badge..."
        )
```

---

## Questions for Decision Makers

1. **Primary Goal:** Is the badge system primarily for:
   - Self-service community recognition (→ use badges2)
   - Curated community recognition (→ use badges3)

2. **Workflow Preference:** Should users:
   - Request badges themselves (→ use badges2)
   - Be added by organization managers (→ use badges3)

3. **Integration:** Should badges:
   - Be standalone feature (→ use badges2)
   - Integrate with contributor system (→ use badges3)

4. **Moderation:** Are we comfortable with:
   - Org managers directly adding badge holders without per-person approval (badges3)
   - User-submitted claims that require per-person approval (badges2)

5. **Images vs Icons:** Preference for:
   - Font Awesome icons (easy, flexible) (→ badges2)
   - Custom badge images (professional, requires workflow) (→ badges3)

6. **Risk Tolerance:** Comfort level with:
   - Modifying existing Contributor model (badges3 does this)
   - Adding new standalone system (badges2 does this)

---

## Conclusion

Both implementations are solid but serve different use cases:

- **badges2** = User-driven, claim-based, standalone badge system
- **badges3** = Org-managed, integrated contributor recognition system

The Contributors Committee patch (badges3) is well-designed and addresses a broader community need, but **requires moderation additions** before deployment to address Magnus's concerns about user-editable published content.

**Recommendation:** Deploy badges3 with moderation enhancements, as it has community backing and solves a larger problem. But recognize it's a different approach than originally discussed with Melanie.
