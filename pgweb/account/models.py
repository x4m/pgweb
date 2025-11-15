from django.db import models
from django.contrib.auth.models import User
from pgweb.core.models import Organisation


class Badge(models.Model):
    """
    Badges created by organizations that users can claim.
    Examples: 'PGConf.dev 2025 Volunteer', 'Postgres 18 Contributor'
    """
    name = models.CharField(max_length=200, null=False, blank=False,
                           help_text="Badge name (e.g., 'PGConf.dev 2025 Volunteer', 'Postgres 18 Contributor')")
    description = models.TextField(null=False, blank=False,
                                   help_text="What this badge represents and how to earn it")
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, 
                                     related_name='badges',
                                     help_text="Organization that created and manages this badge")
    icon = models.CharField(max_length=50, null=False, blank=False, default='fa-trophy',
                           help_text="Font Awesome icon class (e.g., 'fa-trophy', 'fa-star', 'fa-award')")
    color = models.CharField(max_length=20, null=False, blank=False, default='#FFD700',
                            help_text="Badge color in hex format (e.g., '#FFD700' for gold)")
    active = models.BooleanField(null=False, blank=False, default=True,
                                 help_text="Whether users can currently claim this badge")
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='badges_created')
    
    class Meta:
        ordering = ('-created_at', 'name')
        unique_together = (('organisation', 'name'),)
    
    def __str__(self):
        return f"{self.name} ({self.organisation.name})"


class BadgeClaim(models.Model):
    """
    User's request to receive a badge. Requires approval from organization manager.
    """
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'
    
    STATUS_CHOICES = [
        (PENDING, 'Pending Review'),
        (APPROVED, 'Approved'),
        (REJECTED, 'Rejected'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='badge_claims')
    badge = models.ForeignKey(Badge, on_delete=models.CASCADE, related_name='claims')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=PENDING)
    claimed_at = models.DateTimeField(auto_now_add=True)
    message = models.TextField(null=False, blank=True,
                              help_text="User's message explaining why they deserve this badge")
    
    # Approval/rejection info
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='badge_claims_reviewed')
    review_note = models.TextField(null=False, blank=True,
                                   help_text="Reviewer's note about the decision")
    
    class Meta:
        unique_together = (('user', 'badge'),)
        ordering = ('-claimed_at',)
    
    def __str__(self):
        return f"{self.user.username} -> {self.badge.name} ({self.status})"


class UserBadge(models.Model):
    """
    Approved badges that users have earned. Created when BadgeClaim is approved.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='badges')
    badge = models.ForeignKey(Badge, on_delete=models.CASCADE, related_name='awarded_to')
    claim = models.OneToOneField(BadgeClaim, on_delete=models.SET_NULL, null=True, blank=True,
                                 related_name='awarded_badge')
    awarded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = (('user', 'badge'),)
        ordering = ('-awarded_at',)
    
    def __str__(self):
        return f"{self.badge.name} - {self.user.username}"


class CommunityAuthOrg(models.Model):
    orgname = models.CharField(max_length=100, null=False, blank=False, unique=True,
                               help_text="Name of the organisation")
    require_consent = models.BooleanField(null=False, blank=False, default=True)

    def __str__(self):
        return self.orgname


class CommunityAuthSite(models.Model):
    name = models.CharField(max_length=100, null=False, blank=False, unique=True,
                            help_text="Note that the value in this field is shown on the login page, so make sure it's user-friendly!")
    redirecturl = models.URLField(max_length=200, null=False, blank=False)
    apiurl = models.URLField(max_length=200, null=False, blank=True)
    cryptkey = models.CharField(max_length=100, null=False, blank=False,
                                help_text="Use tools/communityauth/generate_cryptkey.py to create a key")
    version = models.IntegerField(choices=((2, "v2 - DEPRECATED"), (3, "v3 - recommended"), (4, "v4 - ChaCha20_Poly1305 compatibility")), default=2)
    comment = models.TextField(null=False, blank=True)
    org = models.ForeignKey(CommunityAuthOrg, null=False, blank=False, on_delete=models.CASCADE)
    cooloff_hours = models.PositiveIntegerField(null=False, blank=False, default=0,
                                                help_text="Number of hours a user must have existed in the systems before allowed to log in to this site")
    cooloff_message = models.TextField(null=False, blank=True,
                                       help_text="Message (HTML format allowed, will be wrapped in <P>) to show users who have not passed the cool-off period")
    push_changes = models.BooleanField(null=False, blank=False, default=False,
                                       help_text="Supports receiving http POSTs with changes to accounts")
    push_ssh = models.BooleanField(null=False, blank=False, default=False,
                                   help_text="Wants to receive SSH keys in push changes")

    def __str__(self):
        return self.name


class CommunityAuthConsent(models.Model):
    user = models.ForeignKey(User, null=False, blank=False, on_delete=models.CASCADE)
    org = models.ForeignKey(CommunityAuthOrg, null=False, blank=False, on_delete=models.CASCADE)
    consentgiven = models.DateTimeField(null=False, blank=False)

    class Meta:
        unique_together = (('user', 'org'), )


class SecondaryEmail(models.Model):
    user = models.ForeignKey(User, null=False, blank=False, on_delete=models.CASCADE)
    email = models.EmailField(max_length=75, null=False, blank=False, unique=True)
    confirmed = models.BooleanField(null=False, blank=False, default=False)
    token = models.CharField(max_length=100, null=False, blank=False)
    sentat = models.DateTimeField(null=False, blank=False, auto_now=True)

    class Meta:
        ordering = ('email', )
