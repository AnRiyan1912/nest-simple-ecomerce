import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDtoSignIn, AuthDtoSignUp } from 'src/dto/auth/auth.dto';
import { Tokens } from './types';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async signUp(dto: AuthDtoSignUp): Promise<Tokens> {
    const argon2 = require('argon2');
    try {
      const hash = await argon2.hash(dto.password);
      const user = await this.prismaService.user.create({
        data: { email: dto.email, username: dto.username, hash: hash },
      });

      const tokens = await this.signToken(user.id, user.email);
      await this.updateRtHash(user.id, tokens.refresh_token);
      return tokens;
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('Credentials Already Taken');
        } else {
          throw err;
        }
      }
    }
  }

  async signIn(dto: AuthDtoSignIn) {
    const argon2 = require('argon2');
    const user = await this.prismaService.user.findFirst({
      where: {
        OR: [{ email: dto.emailOrUsername }, { username: dto.emailOrUsername }],
      },
    });

    if (!user) {
      throw new ForbiddenException('Credentials are incorrect');
    }

    const checkPw = await argon2.verify(user.hash, dto.password);
    if (!checkPw) throw new ForbiddenException('Access Denied');

    if (!checkPw) {
      throw new ForbiddenException('Password is incorrect');
    }

    const tokens = await this.signToken(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async verifyOtpCode(token: string, otp: string): Promise<Boolean> {
    const payloadToken = this.jwtService.decode(token);

    const findUser = await this.prismaService.user.findUnique({
      where: { id: payloadToken.sub },
      select: { email: true, id: true },
    });

    if (!findUser) {
      throw new NotFoundException(
        'Cannot verify otp code because user not registered',
      );
    }

    const findOtp = await this.prismaService.otp.findFirst({
      where: { email: findUser.email },
    });

    if (findOtp.code !== otp) {
      throw new BadRequestException(
        'Otp code not same with wich send to your email',
      );
    }

    return true;
  }

  async signToken(userId: number, email: string): Promise<Tokens> {
    const payload = {
      sub: userId,
      email: email,
    };

    const at_secreet = this.configService.get<string>('JWT_SECRET');
    const rt_secreet = this.configService.get<string>('JWT_SECRET');

    const at_token = await this.jwtService.signAsync(payload, {
      expiresIn: '15min',
      secret: at_secreet,
    });

    const rt_token = await this.jwtService.signAsync(payload, {
      expiresIn: '7d',
      secret: rt_secreet,
    });

    return {
      access_token: at_token,
      refresh_token: rt_token,
    };
  }

  async updateRtHash(userId: number, rt: string) {
    const argon2 = require('argon2');
    const hash = await argon2.hash(rt);

    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }
}
