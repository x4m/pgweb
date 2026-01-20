#!/bin/bash
# Setup database for Contributors Committee badge system demo

set -e  # Exit on error

echo "========================================================================"
echo "SETTING UP CONTRIBUTORS BADGE SYSTEM DATABASE"
echo "========================================================================"

# Check if we're in the right directory
if [ ! -f "manage.py" ]; then
    echo "ERROR: manage.py not found. Please run this script from the pgweb directory."
    exit 1
fi

# Check if virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    echo "⚠️  Virtual environment not activated. Attempting to activate..."
    if [ -d "venv" ]; then
        source venv/bin/activate
        echo "✓ Activated virtual environment"
    else
        echo "ERROR: venv directory not found. Please activate your virtual environment first."
        exit 1
    fi
fi

echo ""
echo "Step 1: Running database migrations..."
echo "----------------------------------------------------------------------"
python manage.py migrate
echo "✓ Migrations complete"

echo ""
echo "Step 2: Creating demo data..."
echo "----------------------------------------------------------------------"
python manage.py shell < setup_badge_demo_data.py

echo ""
echo "========================================================================"
echo "✅ SETUP COMPLETE!"
echo "========================================================================"
echo ""
echo "You can now start the server with:"
echo "  python manage.py runserver 0.0.0.0:8000"
echo ""
echo "Test accounts created:"
echo "  Admin:        admin / admin123"
echo "  Moderator:    moderator / moderator123"
echo "  Org Manager:  orgmanager1 / manager123"
echo "  Badge Holder: alice / alice123"
echo ""
echo "See DEMO_CREDENTIALS.md for complete list and test workflows."
echo ""
