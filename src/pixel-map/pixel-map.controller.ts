import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
} from '@nestjs/common';
import { PixelMapService } from './pixel-map.service';
import { CreatePixelMapDto } from './dto/create-pixel-map.dto';
import { UpdatePixelMapDto } from './dto/update-pixel-map.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';

@ApiTags('Pixel Maps')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('pixel-maps')
export class PixelMapController {
  constructor(private readonly pixelMapService: PixelMapService) {}

  @Get()
  findAll() {
    return this.pixelMapService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.pixelMapService.findOne(id);
  }

  @Post()
  create(@Body() createPixelMapDto: CreatePixelMapDto) {
    return this.pixelMapService.create(createPixelMapDto);
  }

  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updatePixelMapDto: UpdatePixelMapDto,
  ) {
    return this.pixelMapService.update(id, updatePixelMapDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.pixelMapService.remove(id);
  }
}
