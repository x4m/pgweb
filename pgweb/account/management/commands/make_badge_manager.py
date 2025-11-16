from django.core.management.base import BaseCommand
from django.contrib.auth.models import User, Permission
from django.contrib.contenttypes.models import ContentType
from pgweb.core.models import Organisation
from pgweb.account.models import Badge, BadgeClaim


class Command(BaseCommand):
    help = 'Grant badge management permissions to a user for their organizations'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Username to grant permissions to')
        parser.add_argument(
            '--org',
            type=str,
            help='Organization name (if not specified, shows available orgs)',
        )

    def handle(self, *args, **options):
        username = options['username']
        org_name = options.get('org')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'User "{username}" does not exist'))
            return

        # If no org specified, list available organizations
        if not org_name:
            self.stdout.write('\nAvailable organizations:')
            for org in Organisation.objects.filter(approved=True).order_by('name'):
                managers = org.managers.count()
                badges = org.badges.count()
                self.stdout.write(f'  - {org.name} ({managers} managers, {badges} badges)')
            self.stdout.write(f'\nUsage: python manage.py make_badge_manager {username} --org "Organization Name"')
            return

        # Get the organization
        try:
            org = Organisation.objects.get(name=org_name)
        except Organisation.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'Organization "{org_name}" does not exist'))
            return

        # Make user staff
        if not user.is_staff:
            user.is_staff = True
            user.save()
            self.stdout.write(self.style.SUCCESS(f'✓ Granted staff access to {username}'))

        # Grant permissions
        ct_badge = ContentType.objects.get_for_model(Badge)
        ct_claim = ContentType.objects.get_for_model(BadgeClaim)

        permissions = [
            Permission.objects.get(content_type=ct_badge, codename='view_badge'),
            Permission.objects.get(content_type=ct_badge, codename='add_badge'),
            Permission.objects.get(content_type=ct_badge, codename='change_badge'),
            Permission.objects.get(content_type=ct_claim, codename='view_badgeclaim'),
            Permission.objects.get(content_type=ct_claim, codename='change_badgeclaim'),
        ]

        for perm in permissions:
            user.user_permissions.add(perm)

        self.stdout.write(self.style.SUCCESS(f'✓ Granted badge management permissions'))

        # Add as organization manager
        org.managers.add(user)
        self.stdout.write(self.style.SUCCESS(f'✓ Added {username} as manager of {org.name}'))

        # Summary
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('✅ Setup Complete!'))
        self.stdout.write('=' * 60)
        self.stdout.write(f'\nUser: {username}')
        self.stdout.write(f'Organization: {org.name}')
        self.stdout.write(f'Badges in org: {org.badges.count()}')
        self.stdout.write(f'\n{username} can now:')
        self.stdout.write(f'  1. Login to: /admin/')
        self.stdout.write(f'  2. Create badges for {org.name}')
        self.stdout.write(f'  3. Review and approve badge claims')
        self.stdout.write(f'  4. View claims for {org.name} badges only')



