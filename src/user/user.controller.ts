import { Controller, Post, Body, BadRequestException, Get } from '@nestjs/common';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @Post('register')
  async register(@Body() body) {
    const { email, password } = body;
    if (!email || !password) {
        throw new BadRequestException('Email and password cannot be empty');
    }
    return this.userService.registerUser(email, password);
  }

  @Post('login')
  async login(@Body() body) {
    const { email, password } = body;
    if (!email || !password) {
      throw new BadRequestException('Email and password cannot be empty');
    }
    return this.userService.loginUser(email, password);
  }

  @Get('count')
  async getUserCount() {
    const count = await this.userService.countUsers();
    return { count };
  }

}
