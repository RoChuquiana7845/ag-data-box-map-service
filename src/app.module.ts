import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { validateEnv } from './config/config.validation';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { AreaModule } from './area/area.module';
import { SampleModule } from './sample/sample.module';
import { MapModule } from './map/map.module';
import { ClassificationModule } from './classification/classification.module';
import { AttributeModule } from './attribute/attribute.module';
import { SampleGridModule } from './sample-grid/sample-grid.module';
import { PixelSampleModule } from './pixel-sample/pixel-sample.module';
import { PixelMapModule } from './pixel-map/pixel-map.module';
import { SamplePointModule } from './sample-point/sample-point.module';
import { ProjectModule } from './project/project.module';
import { SoilTypeModule } from './soil-type/soil-type.module';
import { UnitMeasureModule } from './unit-measure/unit-measure.module';
import { OrganizationModule } from './organization/organization.module';
import { ClassificationLevelModule } from './classification-level/classification-level.module';
import { ManagementRegionModule } from './management-region/management-region.module';
import { LoggerMiddleware } from './shared/middleware/logger.middleware';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      validate: validateEnv,
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get<string>('DB_HOST'),
        port: configService.get<number>('DB_PORT'),
        username: configService.get<string>('DB_USER'),
        password: configService.get<string>('DB_PASSWORD'),
        database: configService.get<string>('DB_NAME'),
        autoLoadEntities: true,
        synchronize: configService.get<string>('NODE_ENV') === 'development',
        logging: true,
        migrations: [__dirname + '/../migrations/*{.ts,.js}'],
        migrationsTableName: 'migrations',
      }),
    }),
    AuthModule,
    UserModule,
    AreaModule,
    SampleModule,
    MapModule,
    ClassificationModule,
    AttributeModule,
    SampleGridModule,
    PixelSampleModule,
    PixelMapModule,
    SamplePointModule,
    ProjectModule,
    SoilTypeModule,
    UnitMeasureModule,
    OrganizationModule,
    ClassificationLevelModule,
    ManagementRegionModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggerMiddleware).forRoutes('*');
  }
}
