from django.contrib import admin
from django.core.validators import ValidationError
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserChangeForm
from django.contrib.auth.models import User
from django import forms

import base64
import re

from pgweb.util.widgets import TemplateRenderWidget
from pgweb.util.db import exec_to_dict
from pgweb.account.views import OAUTH_PASSWORD_STORE

from .models import CommunityAuthSite, CommunityAuthOrg, SecondaryEmail, Badge, BadgeClaim, UserBadge


class CommunityAuthSiteAdminForm(forms.ModelForm):
    class Meta:
        model = CommunityAuthSite
        exclude = ()

    def clean_cryptkey(self):
        x = None
        try:
            x = base64.b64decode(self.cleaned_data['cryptkey'])
        except Exception:
            raise forms.ValidationError("Crypto key must be base64 encoded")

        if (len(x) != 16 and len(x) != 24 and len(x) != 32 and len(x) != 64):
            raise forms.ValidationError("Crypto key must be 16, 24, 32 or 64 bytes before being base64-encoded")
        return self.cleaned_data['cryptkey']

    def clean(self):
        d = super().clean()

        if 'cryptkey' in self.cleaned_data:
            key = base64.b64decode(self.cleaned_data['cryptkey'])
            if self.cleaned_data['version'] == 2:
                keylen = 32
            elif self.cleaned_data['version'] == 3:
                keylen = 64
            elif self.cleaned_data['version'] == 4:
                keylen = 32
            else:
                self.add_error('version', 'Unknown version')
                keylen = 0
            if len(key) != keylen:
                self.add_error('cryptkey', 'For version {}, crypto keys muyst be {} bytes'.format(self.cleaned_data['version'], keylen))

        if d.get('push_changes', False) and not d.get('apiurl', ''):
            self.add_error('push_changes', 'API url must be specified to enable push changes!')

        if d.get('push_ssh', False) and not d.get('push_changes', False):
            self.add_error('push_ssh', 'SSH changes can only be pushed if general change push is enabled')

        if d.get('cooloff_hours', 0) > 0 and not d.get('cooloff_message', ''):
            self.add_error('cooloff_message', 'Cooloff message must be specified if cooloff period is')

        return d


class CommunityAuthSiteAdmin(admin.ModelAdmin):
    list_display = ('name', 'cooloff_hours', 'push_changes', 'push_ssh', 'version', 'org')
    form = CommunityAuthSiteAdminForm


class PGUserChangeForm(UserChangeForm):
    passwordinfo = forms.CharField(label="Password information", required=False)
    logininfo = forms.CharField(label="Community login history", required=False)
    extraemail = forms.CharField(label="Additional email addresses", required=False)

    def __init__(self, *args, **kwargs):
        super(PGUserChangeForm, self).__init__(*args, **kwargs)
        # because the auth.User model is set to "blank=False" and the Django
        # auth.UserChangeForm is setup as a ModelForm, it will always validate
        # the "username" even though it is not present.  Thus the best way to
        # avoid the validation is to remove the "username" field, if it exists
        if self.fields.get('username'):
            del self.fields['username']

        self.fields['passwordinfo'].widget = TemplateRenderWidget(
            template='forms/widgets/community_auth_password_info.html',
            context={
                'type': self.password_type(self.instance),
            },
        )

        self.fields['logininfo'].widget = TemplateRenderWidget(
            template='forms/widgets/community_auth_usage_widget.html',
            context={
                'logins': exec_to_dict("SELECT s.name AS service, lastlogin, logincount FROM account_communityauthsite s INNER JOIN account_communityauthlastlogin l ON s.id=l.site_id WHERE user_id=%(userid)s ORDER BY lastlogin DESC", {
                    'userid': self.instance.pk,
                }),
            })

        self.fields['email'].help_text = "Be EXTREMELY careful when changing an email address! It is almost ALWAYS better to reset the password on the user and have them change it on their own! Sync issues are common!"
        self.fields['extraemail'].widget = TemplateRenderWidget(
            template='forms/widgets/extra_email_list_widget.html',
            context={
                'emails': SecondaryEmail.objects.filter(user=self.instance).order_by('-confirmed', 'email'),
            },
        )

    def password_type(self, obj):
        if obj.password == OAUTH_PASSWORD_STORE:
            return "OAuth integrated"
        elif obj.password.startswith('pbkdf2_'):
            return "Regular password"
        elif obj.password.startswith('sha1$'):
            return "Old SHA1 password"
        elif re.match('^[a-z0-9]{64}', obj.password):
            return "Old unknown hash"
        else:
            return "Unknown"

    def clean_email(self):
        e = self.cleaned_data['email'].lower()
        if User.objects.filter(email=e).exclude(pk=self.instance.pk):
            raise ValidationError("There already exists a different user with this address")
        if SecondaryEmail.objects.filter(email=e):
            raise ValidationError("This address is already a secondary address attached to a user")

        return e


class PGUserAdmin(UserAdmin):
    """overrides default Django user admin"""
    form = PGUserChangeForm

    def get_readonly_fields(self, request, obj=None):
        """this prevents users from changing a username once created"""
        if obj:
            return self.readonly_fields + ('username',)
        return self.readonly_fields

    @property
    def fieldsets(self):
        fs = list(super().fieldsets)
        fs.append(
            ('Community authentication', {'fields': ('logininfo', )}),
        )
        if 'passwordinfo' not in fs[0][1]['fields']:
            fs[0][1]['fields'] = list(fs[0][1]['fields']) + ['passwordinfo', ]
        if 'extraemail' not in fs[1][1]['fields']:
            fs[1][1]['fields'] = list(fs[1][1]['fields']) + ['extraemail', ]
        return fs

    def has_view_permission(self, request, obj=None):
        """
        We have a special check for view permissions here based on if the user
        has access to modifying contributors. This allows us to allow the
        editor to return a list of usernames from the dropdown. If this is not
        the autocomplete / user editor workflow, then we proceed as normal.
        """
        if request.path == '/admin/autocomplete/' and request.GET.get('app_label') == 'contributors' and request.GET.get('model_name') == 'contributor' and request.user.has_perm("contributors.change_contributor"):
            return True
        return super().has_view_permission(request, obj)

    @property
    def search_fields(self):
        sf = list(super().search_fields)
        return sf + ['secondaryemail__email', ]


class BadgeAdmin(admin.ModelAdmin):
    list_display = ('name', 'organisation', 'active', 'created_at', 'created_by')
    list_filter = ('active', 'organisation', 'created_at')
    search_fields = ('name', 'description', 'organisation__name')
    autocomplete_fields = ('organisation',)
    readonly_fields = ('created_at', 'created_by')
    ordering = ('-created_at',)
    
    def has_module_permission(self, request):
        """Show in admin menu if user has any badge permission"""
        return request.user.has_perm('account.view_badge') or request.user.has_perm('account.add_badge')
    
    def has_add_permission(self, request):
        """Can add if user has permission and manages at least one org"""
        from pgweb.core.models import Organisation
        if not request.user.has_perm('account.add_badge'):
            return False
        if request.user.is_superuser:
            return True
        return Organisation.objects.filter(managers=request.user, approved=True).exists()
    
    def has_view_permission(self, request, obj=None):
        """Can view if user has permission"""
        return request.user.has_perm('account.view_badge')
    
    def has_change_permission(self, request, obj=None):
        """Can change if user manages the badge's org"""
        if not request.user.has_perm('account.change_badge'):
            return False
        if request.user.is_superuser:
            return True
        if obj:
            return obj.organisation.managers.filter(id=request.user.id).exists()
        return True  # For list view
    
    def get_form(self, request, obj=None, **kwargs):
        """Filter organization dropdown to only show orgs user manages"""
        form = super().get_form(request, obj, **kwargs)
        if not request.user.is_superuser:
            from pgweb.core.models import Organisation
            user_orgs = Organisation.objects.filter(managers=request.user, approved=True)
            form.base_fields['organisation'].queryset = user_orgs
            if obj is None and user_orgs.count() == 1:
                # Pre-select if user only manages one org
                form.base_fields['organisation'].initial = user_orgs.first()
        return form
    
    def save_model(self, request, obj, form, change):
        if not obj.pk:  # New badge
            obj.created_by = request.user
            # Ensure user manages the organization
            if not request.user.is_superuser and not obj.organisation.managers.filter(id=request.user.id).exists():
                from django.core.exceptions import PermissionDenied
                raise PermissionDenied("You can only create badges for organizations you manage")
        super().save_model(request, obj, form, change)
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # If user is not superuser, only show badges from their organizations
        if not request.user.is_superuser:
            qs = qs.filter(organisation__managers=request.user)
        return qs


class BadgeClaimAdmin(admin.ModelAdmin):
    list_display = ('user', 'badge', 'status', 'claimed_at', 'reviewed_by')
    list_filter = ('status', 'badge__organisation', 'claimed_at')
    search_fields = ('user__username', 'user__email', 'badge__name', 'message')
    readonly_fields = ('claimed_at', 'reviewed_at', 'reviewed_by')
    autocomplete_fields = ('user',)
    ordering = ('-claimed_at',)
    
    fieldsets = (
        ('Claim Information', {
            'fields': ('user', 'badge', 'status', 'claimed_at', 'message')
        }),
        ('Review Information', {
            'fields': ('reviewed_at', 'reviewed_by', 'review_note')
        }),
    )
    
    def has_module_permission(self, request):
        """Show in admin menu if user has any badge claim permission"""
        return request.user.has_perm('account.view_badgeclaim') or request.user.has_perm('account.change_badgeclaim')
    
    def has_add_permission(self, request):
        """Users can't add claims directly - they must use the claim form"""
        return False
    
    def has_view_permission(self, request, obj=None):
        """Can view if user has permission"""
        return request.user.has_perm('account.view_badgeclaim')
    
    def has_change_permission(self, request, obj=None):
        """Can change if user manages the badge's org"""
        if not request.user.has_perm('account.change_badgeclaim'):
            return False
        if request.user.is_superuser:
            return True
        if obj:
            return obj.badge.organisation.managers.filter(id=request.user.id).exists()
        return True  # For list view
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # If user is not superuser, only show claims for badges from their organizations
        if not request.user.is_superuser:
            qs = qs.filter(badge__organisation__managers=request.user)
        return qs
    
    def save_model(self, request, obj, form, change):
        from django.utils import timezone
        from .models import UserBadge
        
        # Track if status changed to approved
        if change and 'status' in form.changed_data:
            if obj.status == BadgeClaim.APPROVED:
                obj.reviewed_by = request.user
                obj.reviewed_at = timezone.now()
                
                # Create UserBadge if it doesn't exist
                UserBadge.objects.get_or_create(
                    user=obj.user,
                    badge=obj.badge,
                    defaults={'claim': obj}
                )
            elif obj.status == BadgeClaim.REJECTED:
                obj.reviewed_by = request.user
                obj.reviewed_at = timezone.now()
        
        super().save_model(request, obj, form, change)


class UserBadgeAdmin(admin.ModelAdmin):
    list_display = ('user', 'badge', 'awarded_at')
    list_filter = ('badge__organisation', 'awarded_at')
    search_fields = ('user__username', 'user__email', 'badge__name')
    readonly_fields = ('awarded_at',)
    autocomplete_fields = ('user',)
    ordering = ('-awarded_at',)
    
    def has_module_permission(self, request):
        """Show in admin menu if user has badge view permission"""
        from pgweb.core.models import Organisation
        if request.user.is_superuser:
            return True
        return Organisation.objects.filter(managers=request.user, approved=True).exists()
    
    def has_add_permission(self, request):
        """Can't add directly - badges are created when claims are approved"""
        return False
    
    def has_view_permission(self, request, obj=None):
        """Can view if user manages the badge's org"""
        from pgweb.core.models import Organisation
        if request.user.is_superuser:
            return True
        if obj:
            return obj.badge.organisation.managers.filter(id=request.user.id).exists()
        return Organisation.objects.filter(managers=request.user, approved=True).exists()
    
    def has_change_permission(self, request, obj=None):
        """Can't change - badges are read-only"""
        return False
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # If user is not superuser, only show badges from their organizations
        if not request.user.is_superuser:
            qs = qs.filter(badge__organisation__managers=request.user)
        return qs


admin.site.register(Badge, BadgeAdmin)
admin.site.register(BadgeClaim, BadgeClaimAdmin)
admin.site.register(UserBadge, UserBadgeAdmin)
admin.site.register(CommunityAuthSite, CommunityAuthSiteAdmin)
admin.site.register(CommunityAuthOrg)
admin.site.unregister(User)  # have to unregister default User Admin...
admin.site.register(User, PGUserAdmin)  # ...in order to add overrides
