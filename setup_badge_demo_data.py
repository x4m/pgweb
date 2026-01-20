#!/usr/bin/env python
"""
Setup demo data for Contributors Committee badge system (badges3)

This creates:
- Multiple user accounts with different roles
- Organizations with managers
- Badges (approved and pending)
- Badge holders
- Contributor profiles

Run: python manage.py shell < setup_badge_demo_data.py
"""

from django.contrib.auth.models import User, Group
from pgweb.core.models import Organisation, OrganisationType
from pgweb.contributors.models import Badge, Contributor, ContributorType

print("="*70)
print("SETTING UP BADGE DEMO DATA")
print("="*70)

# Load initial fixtures if needed
print("\n1. Loading initial data (if not already loaded)...")
import os
from django.core import management

# Load fixtures for organization and contributor types
fixtures_to_load = [
    ('core', 'data.json'),
    ('contributors', 'data.json'),
]

for app, fixture in fixtures_to_load:
    try:
        management.call_command('loaddata', fixture, app_label=app, verbosity=0)
        print(f"  ✓ Loaded {app}/{fixture}")
    except Exception as e:
        # Fixtures might already be loaded
        print(f"  ℹ {app}/{fixture}: {str(e)[:50]}...")

# Clean up existing test data (optional - be careful in production!)
print("\n2. Cleaning up existing test data...")
try:
    Badge.objects.all().delete()
    print("  ✓ Cleaned up existing badges")
except Exception as e:
    print(f"  ⚠ Could not clean badges (table might not exist yet): {e}")
    
User.objects.filter(username__in=['admin', 'moderator', 'orgmanager1', 'orgmanager2', 'alice', 'bob', 'charlie']).delete()
Organisation.objects.filter(name__contains='Demo').delete()
Contributor.objects.filter(email__contains='example.com').delete()
print("  ✓ Cleaned up existing test users/orgs")

# Get organization types (loaded from fixtures)
print("\n3. Getting organization and contributor types...")
org_type_community = OrganisationType.objects.get(typename='Open Source Project')
org_type_nonprofit = OrganisationType.objects.get(typename='Not for profit')
contrib_type_major = ContributorType.objects.get(typename='Major Contributors')
contrib_type_significant = ContributorType.objects.get(typename='Significant Contributors')
print(f"  ✓ Types loaded from fixtures")

# ============================================================================
# CREATE USERS
# ============================================================================
print("\n4. Creating users...")

# Admin / Superuser
admin = User.objects.create_superuser(
    username='admin',
    email='admin@example.com',
    password='admin123',
    first_name='Admin',
    last_name='User'
)
admin.is_staff = True
admin.save()
print(f"  ✓ Created admin (superuser)")

# Moderator (can access /admin/pending/)
moderator = User.objects.create_user(
    username='moderator',
    email='moderator@example.com',
    password='moderator123',
    first_name='Moderator',
    last_name='User'
)
moderator.is_staff = True
moderator.save()
moderators_group, _ = Group.objects.get_or_create(name='pgweb moderators')
moderator.groups.add(moderators_group)
print(f"  ✓ Created moderator (can approve badges)")

# Organization Manager 1 (PGConf.dev)
orgmanager1 = User.objects.create_user(
    username='orgmanager1',
    email='manager1@example.com',
    password='manager123',
    first_name='Sarah',
    last_name='Conference'
)
print(f"  ✓ Created orgmanager1 (will manage PGConf.dev)")

# Organization Manager 2 (PostgreSQL Extension Project)
orgmanager2 = User.objects.create_user(
    username='orgmanager2',
    email='manager2@example.com',
    password='manager123',
    first_name='David',
    last_name='Extension'
)
print(f"  ✓ Created orgmanager2 (will manage Extension Project)")

# Regular users (potential badge holders)
alice = User.objects.create_user(
    username='alice',
    email='alice@example.com',
    password='alice123',
    first_name='Alice',
    last_name='Developer'
)
print(f"  ✓ Created alice (badge holder)")

bob = User.objects.create_user(
    username='bob',
    email='bob@example.com',
    password='bob123',
    first_name='Bob',
    last_name='Speaker'
)
print(f"  ✓ Created bob (badge holder)")

charlie = User.objects.create_user(
    username='charlie',
    email='charlie@example.com',
    password='charlie123',
    first_name='Charlie',
    last_name='Volunteer'
)
print(f"  ✓ Created charlie (badge holder)")

# ============================================================================
# CREATE ORGANIZATIONS
# ============================================================================
print("\n5. Creating organizations...")

org_pgconf = Organisation.objects.create(
    name='Demo PGConf.dev',
    orgtype=org_type_community,
    approved=True,
    address='123 Conference St, Berlin, Germany',
    url='https://pgconf.dev'
)
org_pgconf.managers.add(orgmanager1)
print(f"  ✓ Created organization: {org_pgconf.name}")
print(f"    Manager: {orgmanager1.username}")

org_extension = Organisation.objects.create(
    name='Demo PostgreSQL Extension Project',
    orgtype=org_type_community,
    approved=True,
    address='456 Open Source Ave',
    url='https://github.com/demo/pg-extension'
)
org_extension.managers.add(orgmanager2)
print(f"  ✓ Created organization: {org_extension.name}")
print(f"    Manager: {orgmanager2.username}")

org_company = Organisation.objects.create(
    name='Demo PostgreSQL Company',
    orgtype=org_type_nonprofit,
    approved=True,
    address='789 Business Blvd',
    url='https://demo-pg-company.com'
)
org_company.managers.add(orgmanager1, orgmanager2)
print(f"  ✓ Created organization: {org_company.name}")
print(f"    Managers: {orgmanager1.username}, {orgmanager2.username}")

# ============================================================================
# CREATE BADGES
# ============================================================================
print("\n6. Creating badges...")

# Badge 1: Approved & Active - PGConf.dev 2025 Speaker
badge_speaker = Badge.objects.create(
    org=org_pgconf,
    badge='PGConf.dev 2025 Speaker',
    description='Presented a talk at PGConf.dev 2025 in Berlin',
    url='https://pgconf.dev/2025/schedule',
    image='https://via.placeholder.com/150/4CAF50/FFFFFF?text=Speaker',
    contact='speakers@pgconf.dev',
    approved=True,
    sortorder=10
)
badge_speaker.holders.add(alice, bob)
print(f"  ✓ Badge: {badge_speaker.badge}")
print(f"    Status: APPROVED")
print(f"    Holders: alice, bob")

# Badge 2: Approved & Active - PGConf.dev 2025 Volunteer
badge_volunteer = Badge.objects.create(
    org=org_pgconf,
    badge='PGConf.dev 2025 Volunteer',
    description='Volunteered at PGConf.dev 2025, helping with registration, speaker support, or event logistics',
    url='https://pgconf.dev/2025/volunteers',
    image='https://via.placeholder.com/150/2196F3/FFFFFF?text=Volunteer',
    contact='volunteer@pgconf.dev',
    approved=True,
    sortorder=20
)
badge_volunteer.holders.add(alice, charlie)
print(f"  ✓ Badge: {badge_volunteer.badge}")
print(f"    Status: APPROVED")
print(f"    Holders: alice, charlie")

# Badge 3: Approved & Active - PostgreSQL 18 Contributor
badge_pg18 = Badge.objects.create(
    org=org_company,
    badge='PostgreSQL 18 Contributor',
    description='Contributed code, documentation, or testing to PostgreSQL 18 release',
    url='https://www.postgresql.org/docs/18/release-18.html',
    image='https://via.placeholder.com/150/9C27B0/FFFFFF?text=PG18',
    contact='contributors@postgresql.org',
    approved=True,
    sortorder=5
)
badge_pg18.holders.add(alice, bob, charlie)
print(f"  ✓ Badge: {badge_pg18.badge}")
print(f"    Status: APPROVED")
print(f"    Holders: alice, bob, charlie")

# Badge 4: PENDING APPROVAL - Extension Contributor
badge_extension = Badge.objects.create(
    org=org_extension,
    badge='Demo Extension Contributor',
    description='Contributed to the Demo PostgreSQL Extension project',
    url='https://github.com/demo/pg-extension',
    image='https://via.placeholder.com/150/FF9800/FFFFFF?text=Extension',
    contact='maintainers@demo-extension.org',
    approved=False,  # PENDING!
    sortorder=30
)
# Can add holders even before approval
badge_extension.holders.add(bob)
print(f"  ✓ Badge: {badge_extension.badge}")
print(f"    Status: PENDING APPROVAL ⚠️")
print(f"    Holders: bob (not visible until approved)")

# Badge 5: Approved - Community Moderator
badge_moderator = Badge.objects.create(
    org=org_company,
    badge='Community Moderator 2025',
    description='Helped moderate PostgreSQL community forums and mailing lists',
    url='https://www.postgresql.org/community/',
    image='https://via.placeholder.com/150/607D8B/FFFFFF?text=Mod',
    contact='community@postgresql.org',
    approved=True,
    sortorder=15
)
badge_moderator.holders.add(charlie)
print(f"  ✓ Badge: {badge_moderator.badge}")
print(f"    Status: APPROVED")
print(f"    Holders: charlie")

# ============================================================================
# CREATE CONTRIBUTOR PROFILES
# ============================================================================
print("\n7. Creating contributor profiles...")

# Alice has badges and created a profile
contrib_alice = Contributor.objects.create(
    user=alice,
    firstname='Alice',
    lastname='Developer',
    email='alice@example.com',
    company='Tech Corp',
    companyurl='https://techcorp.example.com',
    location='San Francisco, USA',
    contribution='I have been contributing to PostgreSQL for 3 years. I speak at conferences and help with extension development. I also volunteer at community events.',
    ctype=None  # Not a "recognized contributor" (ctype is nullable now)
)
print(f"  ✓ Profile: {contrib_alice} (has public profile)")

# Bob has badges and created a profile
contrib_bob = Contributor.objects.create(
    user=bob,
    firstname='Bob',
    lastname='Speaker',
    email='bob@example.com',
    location='Berlin, Germany',
    contribution='PostgreSQL enthusiast and conference speaker. I love sharing knowledge about advanced PostgreSQL features.',
    ctype=None
)
print(f"  ✓ Profile: {contrib_bob} (has public profile)")

# Charlie has badges but NO profile (hasn't opted in)
print(f"  ✓ charlie has badges but no profile (not opted in)")

# Create a "recognized contributor" (existing system)
contrib_major = Contributor.objects.create(
    firstname='Major',
    lastname='Contributor',
    email='major@postgresql.org',
    ctype=contrib_type_major,  # Recognized major contributor
    contribution='Core PostgreSQL committer since 2010',
    user=None  # No user account linked
)
print(f"  ✓ Profile: {contrib_major} (recognized major contributor)")

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "="*70)
print("DEMO DATA SETUP COMPLETE!")
print("="*70)

print("\n📋 USER ACCOUNTS:")
print("-" * 70)
print("Role              | Username     | Password     | Description")
print("-" * 70)
print("Superuser         | admin        | admin123     | Full access")
print("Moderator         | moderator    | moderator123 | Approve badges")
print("Org Manager       | orgmanager1  | manager123   | Manage PGConf.dev")
print("Org Manager       | orgmanager2  | manager123   | Manage Extension Project")
print("Badge Holder      | alice        | alice123     | Has 3 badges + profile")
print("Badge Holder      | bob          | bob123       | Has 2 badges + profile")
print("Badge Holder      | charlie      | charlie123   | Has 2 badges, no profile")

print("\n🏢 ORGANIZATIONS:")
print("-" * 70)
print(f"- {org_pgconf.name}")
print(f"  Manager: orgmanager1")
print(f"- {org_extension.name}")
print(f"  Manager: orgmanager2")
print(f"- {org_company.name}")
print(f"  Managers: orgmanager1, orgmanager2")

print("\n🏆 BADGES:")
print("-" * 70)
approved_badges = Badge.objects.filter(approved=True)
pending_badges = Badge.objects.filter(approved=False)
print(f"✅ APPROVED ({approved_badges.count()}):")
for badge in approved_badges:
    holders = badge.holders.all()
    holder_names = ", ".join([u.username for u in holders])
    print(f"  - {badge.badge}")
    print(f"    Holders: {holder_names if holder_names else 'none'}")

print(f"\n⚠️  PENDING APPROVAL ({pending_badges.count()}):")
for badge in pending_badges:
    holders = badge.holders.all()
    holder_names = ", ".join([u.username for u in holders])
    print(f"  - {badge.badge}")
    print(f"    Holders: {holder_names if holder_names else 'none'} (not visible)")

print("\n👤 CONTRIBUTOR PROFILES:")
print("-" * 70)
profiles_with_user = Contributor.objects.filter(user__isnull=False)
print(f"Public profiles: {profiles_with_user.count()}")
for contrib in profiles_with_user:
    print(f"  - {contrib.user.username}: /community/people/{contrib.user.username}/")

print("\n🔗 KEY URLS TO TEST:")
print("-" * 70)
print("PUBLIC PAGES:")
print("  /community/people/                     - All badge holders & badges")
print("  /community/people/alice/               - Alice's profile (has badges)")
print("  /community/people/bob/                 - Bob's profile")
print("  /community/badge/1/                    - PGConf.dev 2025 Speaker badge")
print("  /community/badge/2/                    - PGConf.dev 2025 Volunteer badge")
print("  /community/contributors/               - Recognized contributors (traditional)")
print()
print("ADMIN PAGES:")
print("  /admin/                                - Django admin")
print("  /admin/pending/                        - Pending moderation (moderator)")
print()
print("ACCOUNT PAGES:")
print("  /account/profile/                      - Edit profile (alice/bob/charlie)")
print("  /account/edit/badges/                  - Manage badges (orgmanager1/2)")
print("  /account/edit/badges/1/                - Edit badge #1")

print("\n📖 WORKFLOWS TO TEST:")
print("-" * 70)
print("\n1. ORG MANAGER CREATES BADGE:")
print("   Login as: orgmanager1 / manager123")
print("   Go to: /account/edit/badges/")
print("   Click: Submit new contributor badge")
print("   Fill form, submit")
print("   Result: Badge created with approved=False")

print("\n2. MODERATOR APPROVES BADGE:")
print("   Login as: moderator / moderator123")
print("   Go to: /admin/pending/")
print("   Find pending badge, click to review")
print("   Click 'Approve'")
print("   Result: Badge now visible at /community/badge/X/")

print("\n3. ORG MANAGER ADDS BADGE HOLDERS:")
print("   Login as: orgmanager1 / manager123")
print("   Go to: /account/edit/badges/1/")
print("   In 'add_holder' field, enter: alice@example.com")
print("   Submit")
print("   Result: Alice added as badge holder")

print("\n4. USER CREATES PUBLIC PROFILE:")
print("   Login as: charlie / charlie123")
print("   Go to: /account/profile/")
print("   Check: 'Create publicly visible profile page'")
print("   Fill in bio (contribution field)")
print("   Submit")
print("   Result: Profile visible at /community/people/charlie/")

print("\n5. VIEW BADGE HOLDERS:")
print("   Go to: /community/badge/1/ (PGConf.dev 2025 Speaker)")
print("   See: List of badge holders with links to profiles")
print("   Note: Only users with profiles are shown")

print("\n6. VIEW ALL BADGES & PEOPLE:")
print("   Go to: /community/people/")
print("   See: All badge holders + all approved badges")

print("\n" + "="*70)
print("🚀 Ready to demo! Start at: http://your-vm-ip:8000/")
print("="*70)
