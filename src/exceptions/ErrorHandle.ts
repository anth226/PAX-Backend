import { HttpException } from '@nestjs/common';

export const ErrorHandle = (error: any) => {
  throw error;
  throw new HttpException(error.message ?? 'Internal Server Error', error.status || 500);
};
