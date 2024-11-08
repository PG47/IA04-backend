import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';
import { CanActivate, ExecutionContext,UnauthorizedException } from '@nestjs/common';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  handleRequest(err, user, info) {
    if (info) {
      if (info.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Token has expired, please log in again.');
      }
      throw new UnauthorizedException('Invalid or missing token');
    }
    return user;
  }
}
