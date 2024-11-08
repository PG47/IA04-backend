import { Controller, Post, Body, BadRequestException, Get, UseGuards, Request, ConflictException } from '@nestjs/common';
import { UserService } from './user.service';
import { JwtService } from '@nestjs/jwt';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';

@Controller('user')
export class UserController {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  @Post('register')
  async register(@Body() body) {
    const { email, password } = body;
    if (!email || !password) {
      throw new BadRequestException('Email and password cannot be empty');
    }
    try {
      const result = await this.userService.registerUser(email, password);
    } catch (error) {
      throw new ConflictException('Error registering user');
    }
  }

  @Post('login')
  async login(@Body() body) {
    const { email, password } = body;
    if (!email || !password) {
      throw new BadRequestException('Email and password cannot be empty');
    }
    try {
      const user = await this.userService.loginUser(email, password);

      const token = this.jwtService.sign({ email: user.email, userId: user._id });
      return {
        message: 'Logged in successfully',
        token,
        user: { email: user.email },
      };
    } catch (error) {
      throw new ConflictException('Email or password is incorrect!');
    }
  }

  @UseGuards(JwtAuthGuard)  
  @Get('count')
  async getUserCount(@Request() req) {
    try {
      const count = await this.userService.countUsers();
      return { count };
    } catch (error) {
      throw new ConflictException('Error fetching user count');
    }
  }
}
