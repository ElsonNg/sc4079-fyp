function authorize(user, resource) {
  if (user.isAdmin) {
    return true;
  }
  if (resource.owner === user.id) {
    return true;
  }
  return false;
}
