import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map, catchError } from 'rxjs/operators';

@Injectable()
export class ResponseInterceptor<T>
  implements NestInterceptor<T, { status: string; data: T }>
{
  intercept(
    context: ExecutionContext,
    next: CallHandler<T>,
  ): Observable<{ status: string; data: T }> {
    return next.handle().pipe(
      map((data) => ({
        status: 'success',
        data,
      })),
      catchError((err) => {
        throw new Error(
          err instanceof Error ? err.message : 'Internal server error',
        );
      }),
    );
  }
}
