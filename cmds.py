# app/commands.py

import click
from flask import Flask
from flask.cli import with_appcontext
from models import db,User

def register_commands(app: Flask):

    @app.cli.command('create-admin')
    @click.argument('username')
    @click.argument('password')
    @with_appcontext
    def create_admin(username, password):
        """Create an admin user."""
        admin_user = User(username=username, password=password, role='admin')
        db.session.add(admin_user)
        try:
            db.session.commit()
            click.echo(f"Admin user '{username}' created successfully.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Failed to create admin user: {e}")

    @app.cli.command('init-db')
    @with_appcontext
    def init_db():
        """Initialize the database."""
        db.create_all()
        click.echo('Initialized the database.')
