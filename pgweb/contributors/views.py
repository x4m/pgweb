from django.shortcuts import get_object_or_404
from pgweb.util.contexts import render_pgweb

from .models import ContributorType, Contributor, Badge


def completelist(request):
    contributortypes = list(ContributorType.objects.all())
    return render_pgweb(request, 'community', 'contributors/list.html', {
        'contributortypes': contributortypes,
    })


def peoplelist(request):
    people = list(Contributor.objects.all())
    badges = list(Badge.objects.filter(approved=True))
    return render_pgweb(request, 'community', 'contributors/people.html', {
        'people': people,
        'badges': badges,
    })


def badge_view(request, badgeid):
    badge = get_object_or_404(Badge, id=badgeid, approved=True)
    return render_pgweb(request, 'community', 'contributors/badge.html', {
        'badge': badge,
    })


def profile(request, username):
    contributor = get_object_or_404(Contributor, user__username=username)
    badges = list(Badge.objects.filter(approved=True, holders=contributor.user))
    return render_pgweb(request, 'community', 'contributors/profile.html', {
        'contributor': contributor,
        'badges': badges,
    })
