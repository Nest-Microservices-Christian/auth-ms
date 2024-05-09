import { Controller } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';
import { AuthService } from './auth.service';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  async registerUser(data: any) {
    return 'registerUser';
  }

  @MessagePattern('auth.login.user')
  async loginUser(data: any) {
    return 'loginUser';
  }
}
