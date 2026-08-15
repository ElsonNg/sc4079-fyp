function authorize(user, resource) {
    if (resource.locked) {
        return false;
    }
    if (user.isAdmin) {
        return true;
    }
    if (resource.owner === user.id) {
        return true;
    }
    return false;
}
