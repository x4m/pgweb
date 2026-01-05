from django import forms
from django.forms import ValidationError
from django.conf import settings

from pgweb.core.models import Organisation
from .models import Contributor, Badge
from django.contrib.auth.models import User

from pgweb.util.middleware import get_current_user
from pgweb.mailqueue.util import send_simple_mail


class UserModelMultipleChoiceField(forms.ModelMultipleChoiceField):
    def label_from_instance(self, obj):
        contributor = Contributor.objects.filter(user=obj.pk)
        if contributor:
            return f"{obj.first_name} {obj.last_name} ({obj.username}) <{obj.email}>"
        else:
            return f"{obj.first_name} {obj.last_name} ({obj.username}) <{obj.email}> (not a contributor yet)"


class BadgeForm(forms.ModelForm):
    form_intro = 'Contributor badges acknowledge people contributing time to the PostgreSQL project and the ecosystem around it. If you manage an organisation that gives people the opportunity to contribute (like volunteering or speaking at a conference, writing code for an extension, translating messages, helping others use PostgreSQL, organise the community, ...), you can issue a badge to acknowledge these contributions.'

    remove_holder = UserModelMultipleChoiceField(required=False, queryset=None, label="Current badge holders", help_text="Select one or more users to remove")
    add_holder = forms.CharField(required=False, help_text="Enter email addresses of postgresql.org user accounts to award the badge to. Separate multiple addresses with whitespace.")

    fieldsets = [
        {
            'id': 'general',
            'legend': 'Contributor Badge',
            'fields': ['org', 'badge', 'description', 'url', 'image', 'contact', ],
        },
        {
            'id': 'holders',
            'legend': 'Badge Holders',
            'fields': ['remove_holder', 'add_holder'],
        },
    ]

    class Meta:
        model = Badge
        exclude = ('approved', 'sortorder', 'holders',)

    def __init__(self, *args, **kwargs):
        super(BadgeForm, self).__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields['remove_holder'].queryset = self.instance.holders
        else:
            del self.fields['remove_holder']
            del self.fields['add_holder']
            # remove the holders fieldset
            self.fieldsets = [fs for fs in self.fieldsets if fs['id'] != 'holders']

    def clean_add_holder(self):
        if self.cleaned_data['add_holder']:
            for u in self.cleaned_data['add_holder'].split():
                # something was added - let's make sure the user exists
                try:
                    User.objects.get(email=u.lower())
                except User.DoesNotExist:
                    raise ValidationError("User with email %s not found" % u)

        return self.cleaned_data['add_holder']

    def save(self, commit=True):
        model = super(BadgeForm, self).save(commit=False)

        ops = []

        if 'add_holder' in self.cleaned_data and self.cleaned_data['add_holder']:
            for u in self.cleaned_data['add_holder'].split():
                user = User.objects.get(email=u.lower())
                model.holders.add(user)
                ops.append('Added badge holder {}'.format(user.username))
        if 'remove_holder' in self.cleaned_data and self.cleaned_data['remove_holder']:
            for toremove in self.cleaned_data['remove_holder']:
                model.holders.remove(toremove)
                ops.append('Removed badge holder {}'.format(toremove.username))

        if ops:
            send_simple_mail(
                settings.NOTIFICATION_FROM,
                settings.NOTIFICATION_EMAIL,
                "{0} modified {1}".format(get_current_user().username, model),
                "The following changes were made to {}:\n\n{}".format(model, "\n".join(ops))
            )

        return model

    def filter_by_user(self, user):
        self.fields['org'].queryset = Organisation.objects.filter(managers=user, approved=True)
