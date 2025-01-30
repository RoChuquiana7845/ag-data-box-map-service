import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  SetMetadata,
} from '@nestjs/common';
import { ClassificationLevelService } from './classification-level.service';
import { CreateClassificationLevelDto } from './dto/create-classification-level.dto';
import { UpdateClassificationLevelDto } from './dto/update-classification-level.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { RolesGuard } from 'src/auth/guards/roles.guard';

@ApiTags('Classification Levels')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('classification-levels')
export class ClassificationLevelController {
  constructor(
    private readonly classificationLevelService: ClassificationLevelService,
  ) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.classificationLevelService.findAll();
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.classificationLevelService.findOne(id);
  }

  @SetMetadata('roles', ['admin'])
  @Post()
  create(@Body() createClassificationLevelDto: CreateClassificationLevelDto) {
    return this.classificationLevelService.create(createClassificationLevelDto);
  }

  @SetMetadata('roles', ['admin'])
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateClassificationLevelDto: UpdateClassificationLevelDto,
  ) {
    return this.classificationLevelService.update(
      id,
      updateClassificationLevelDto,
    );
  }

  @SetMetadata('roles', ['admin'])
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.classificationLevelService.remove(id);
  }
}
