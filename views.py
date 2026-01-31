from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist

from .models import Profile


# =======================
# SIGNUP VIEW
# =======================
def signup_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        reg = request.POST.get('reg_no')

        if password1 != password2:
            messages.error(request, "Passwords do not match")
            return redirect('signup')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
            return redirect('signup')

        if Profile.objects.filter(reg=reg).exists():
            messages.error(request, "Registration number already registered")
            return redirect('signup')

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password1
        )

        Profile.objects.create(user=user, reg=reg)

        messages.success(request, "Account created successfully")
        return redirect('login')

    return render(request, 'signup.html')


# =======================
# LOGIN VIEW
# =======================
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == "POST":
        username = request.POST.get('username')
        reg = request.POST.get('reg_no')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is None:
            messages.error(request, "Invalid username or password")
            return redirect('login')

        try:
            profile = user.profile
        except ObjectDoesNotExist:
            messages.error(request, "Profile not found")
            return redirect('login')

        if profile.reg != reg:
            messages.error(request, "Invalid registration number")
            return redirect('login')

        login(request, user)
        return redirect('dashboard')

    return render(request, 'login.html')


# =======================
# DASHBOARD VIEW
# =======================
@login_required(login_url='login')
def dashboard_view(request):
    return render(request, 'dashboard.html')


# =======================
# LOGOUT VIEW
# =======================
@login_required(login_url='login')
def logout_view(request):
    logout(request)
    messages.success(request, "You have logged out successfully")
    return redirect('login')


# =======================
# HOME VIEW (OPTIONAL)
# =======================
def home_view(request):
    return render(request, 'home.html')
