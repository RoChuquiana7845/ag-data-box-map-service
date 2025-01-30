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
import { ClassificationService } from './classification.service';
import { CreateClassificationDto } from './dto/create-classification.dto';
import { UpdateClassificationDto } from './dto/update-classification.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { RolesGuard } from 'src/auth/guards/roles.guard';

@ApiTags('Classifications')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('classifications')
export class ClassificationController {
  constructor(private readonly classificationService: ClassificationService) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.classificationService.findAll();
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.classificationService.findOne(id);
  }

  @SetMetadata('role', 'admin')
  @Post()
  create(@Body() createClassificationDto: CreateClassificationDto) {
    return this.classificationService.create(createClassificationDto);
  }

  @SetMetadata('role', 'admin')
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateClassificationDto: UpdateClassificationDto,
  ) {
    return this.classificationService.update(id, updateClassificationDto);
  }

  @SetMetadata('role', 'admin')
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.classificationService.remove(id);
  }
}
