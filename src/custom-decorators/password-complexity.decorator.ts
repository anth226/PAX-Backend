import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';

@ValidatorConstraint({ name: 'passwordComplexity', async: false })
export class PasswordComplexityConstraint implements ValidatorConstraintInterface {
  validate(value: string, args: ValidationArguments) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(value);
  }

  defaultMessage(args: ValidationArguments) {
    return 'Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character.';
  }
}

export function PasswordComplexity(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: PasswordComplexityConstraint,
    });
  };
}
