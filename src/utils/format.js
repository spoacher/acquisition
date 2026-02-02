export const formatValidationError =(errors) => {
  if(!errors || !errors.issues || errors.length === 0) return 'Validation failed';
  if(Array.isArray(errors.issues)) return errors.issues.map(i => i.message).join(', ');

  return JSON.stringify(errors);
};