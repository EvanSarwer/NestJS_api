import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError, PrismaClientUnknownRequestError } from "@prisma/client/runtime";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) {}

    async signup(dto: AuthDto) {
        // generate the password hash
        const hash = await argon.hash(dto.password);
        // save the new user in the db
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
                // select: {                   // only specific field will return
                //     id: true,
                //     email: true,
                //     createdAt: true,
                // }
            });
    
            delete user.hash;              // another way to not return data
            // return the saved user
            return user;

        } catch (error) {
            if ( error instanceof PrismaClientKnownRequestError ) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credentials taken');
                }
                throw new ForbiddenException('Credentials taken');
            }
            // throw error;
            throw new ForbiddenException('Credentials taken');
        }
        
    }

    async signin(dto: AuthDto) {
        // find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });
        // if user doesn't exist throw exception
        if (!user) {
            throw new ForbiddenException('Credentials incorrect');
        }
        // compare password
        const pwMatches = await argon.verify(user.hash, dto.password);
        // if password incorrect throw exception
        if (!pwMatches){
            throw new ForbiddenException('Credentials incorrect');
        }
        // send back the user
        delete user.hash;
        return user;
    }
}