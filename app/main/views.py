from flask import render_template, redirect, url_for, abort, flash, request,\
    current_app, make_response
from flask.ext.login import login_required, current_user
from flask.ext.sqlalchemy import get_debug_queries
from . import main
from .forms import EditProfileForm, EditProfileAdminForm, MachineForm,\
    CommentForm
from .. import db
from ..models import Permission, Role, User, Machine, Comment
from ..decorators import admin_required, permission_required


@main.after_app_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= current_app.config['RIVALROCKETS_SLOW_DB_QUERY_TIME']:
            current_app.logger.warning(
                'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'
                % (query.statement, query.parameters, query.duration,
                   query.context))
    return response


@main.route('/shutdown')
def server_shutdown():
    if not current_app.testing:
        abort(404)
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if not shutdown:
        abort(500)
    shutdown()
    return 'Shutting down...'


@main.route('/', methods=['GET', 'POST'])
def index():
    form = MachineForm()
    if current_user.can(Permission.CREATE_MACHINE_DATA) and \
            form.validate_on_submit():
        machine = Machine(system_name=form.system_name,
                    author=current_user._get_current_object())
        db.session.add(machine)
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    query = Machine.query
    pagination = query.order_by(Machine.timestamp.desc()).paginate(
        page, per_page=current_app.config['RIVALROCKETS_MACHINES_PER_PAGE'],
        error_out=False)
    machines = pagination.items
    return render_template('index.html', form=form, machines=machines,
                           pagination=pagination)


@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    pagination = user.machines.order_by(Machine.timestamp.desc()).paginate(
        page, per_page=current_app.config['RIVALROCKETS_MACHINES_PER_PAGE'],
        error_out=False)
    machines = pagination.items
    return render_template('user.html', user=user, machines=machines,
                           pagination=pagination)


@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash('Your profile has been updated.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)


@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('The profile has been updated.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)


@main.route('/machine/new', methods=['GET', 'POST'])
@login_required
def new_machine():
    form = MachineForm()
    if current_user.can(Permission.CREATE_MACHINE_DATA) and \
            form.validate_on_submit():
        machine = Machine(system_name=form.system_name.data,
                    system_notes=form.system_notes.data,
                    owner=form.owner.data,
                    author=current_user._get_current_object())
        db.session.add(machine)
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    query = Machine.query
    pagination = query.order_by(Machine.timestamp.desc()).paginate(
        page, per_page=current_app.config['RIVALROCKETS_MACHINES_PER_PAGE'],
        error_out=False)
    machines = pagination.items
    return render_template('new_machine.html', form=form, machines=machines,
                           pagination=pagination)


@main.route('/machine/<int:id>', methods=['GET', 'POST'])
def machine(id):
    machine = Machine.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data,
                          machine=machine,
                          author=current_user._get_current_object())
        db.session.add(comment)
        flash('Your comment has been published.')
        return redirect(url_for('.machine', id=machine.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (machine.comments.count() - 1) // \
            current_app.config['RIVALROCKETS_COMMENTS_PER_PAGE'] + 1
    pagination = machine.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=current_app.config['RIVALROCKETS_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('machine.html', machines=[machine], form=form,
                           comments=comments, pagination=pagination)


@main.route('/machine/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    machine = Machine.query.get_or_404(id)
    if current_user != machine.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = MachineForm()
    if form.validate_on_submit():
        machine.system_name = form.system_name.data
        machine.system_notes = form.system_notes.data
        machine.owner = form.owner.data
        db.session.add(machine)
        flash('The machine information has been updated.')
        return redirect(url_for('.machine', id=machine.id))
    form.system_name.data = machine.system_name
    form.system_notes.data = machine.system_notes
    form.owner.data = machine.owner
    return render_template('edit_machine.html', form=form)

@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('.index')))
    return resp


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
            page, per_page=current_app.config['RIVALROCKETS_COMMENTS_PER_PAGE'],
            error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments,
            pagination=pagination, page=page)


@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    db.session.add(comment)
    return redirect(url_for('.moderate',
        page=request.args.get('page', 1, type=int)))


@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    db.session.add(comment)
    return redirect(url_for('.moderate',
        page=request.args.get('page', 1, type=int)))
